/// Shared helpers for the pqforge CLI commands: option wiring, key and envelope
/// I/O, passphrase resolution, path safety, and small format utilities.
///
/// Everything here is intentionally presentation-free — it returns values and
/// throws [PqForgeException] on misuse; commands own all styled output.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:pqforge/pqforge.dart';

// --- key kinds the CLI writes for classical material -----------------------
//
// The library's PqKeyKind covers ML-KEM/ML-DSA; these CLI-local kinds label the
// classical key files keygen emits. The kind string is bound into the wrapped
// key's AAD, so an Ed25519 secret can never silently unwrap as an ECDSA secret.

const String classicalSignaturePublicKind = 'classical-signature-public';
const String classicalSignatureSecretKind = 'classical-signature-secret';
const String classicalKexPublicKind = 'classical-kex-public';
const String classicalKexSecretKind = 'classical-kex-secret';

// --- option wiring ---------------------------------------------------------

/// Adds the optional envelope-signing options (and, when [includeProfile] is
/// set, the composition `--profile`) shared by the encryption commands.
void addEnvelopeOptions(ArgParser parser, {required bool includeProfile}) {
  if (includeProfile) {
    parser.addOption(
      'profile',
      allowed: const ['compact', 'balanced', 'maximum'],
      defaultsTo: 'maximum',
      help: 'Envelope composition profile.',
      valueHelp: 'name',
    );
  }
  if (includeProfile) {
    parser
      ..addOption(
        'kem',
        allowed: const ['compact', 'balanced', 'maximum'],
        help: 'Override just the ML-KEM strength (defaults to --profile).',
        valueHelp: 'name',
      )
      ..addOption(
        'sig',
        allowed: const ['compact', 'balanced', 'maximum'],
        help:
            'Override just the ML-DSA signature strength (defaults to '
            '--profile). Lets bulk payloads keep a strong KEM with a lighter '
            'signature.',
        valueHelp: 'name',
      );
  }
  parser
    ..addOption(
      'signer-secret',
      help: 'Optional raw or wrapped ML-DSA secret key JSON to sign envelopes.',
      valueHelp: 'file',
    )
    ..addOption(
      'signer-key-id',
      help: 'Optional signer key id recorded in envelope metadata.',
      valueHelp: 'id',
    );
}

/// Adds the AEAD engine selector shared by the bulk encrypt/decrypt commands.
void addEngineOption(ArgParser parser) {
  parser.addOption(
    'engine',
    allowed: const ['cryptography', 'pure-dart'],
    defaultsTo: 'cryptography',
    help:
        'Bulk AEAD engine. "cryptography" is ~10x faster and hardware-backed '
        'where available; "pure-dart" is the PointyCastle reference. Outputs '
        'are byte-compatible either way.',
    valueHelp: 'name',
  );
}

/// Adds the AEAD cipher-suite selector to an encrypt-side command. Decrypt
/// commands need no flag: containers record a non-default suite in their
/// metadata and the open paths rebuild the engine to match.
void addCipherOption(ArgParser parser) {
  parser.addOption(
    'cipher',
    allowed: const ['aes-256-gcm', 'chacha20-poly1305'],
    defaultsTo: 'aes-256-gcm',
    help:
        'Bulk AEAD suite. ChaCha20-Poly1305 is constant-time in software and '
        'typically faster on CPUs without AES instructions; decrypt '
        'auto-detects it from the container.',
    valueHelp: 'suite',
  );
}

/// Resolves `--cipher` into a suite (default AES-256-GCM).
PqForgeCipherSuite cipherFrom(ArgResults results) =>
    PqForgeCipherSuite.byId(results['cipher'] as String? ?? 'aes-256-gcm');

/// Adds the hybrid (ML-KEM + X25519) options to an encrypt-side command.
void addHybridEncryptOptions(ArgParser parser) {
  parser
    ..addFlag(
      'hybrid',
      negatable: false,
      help:
          'Hybrid ML-KEM + X25519 encryption using the conventional '
          '<key-id>.x25519.public.json next to each --recipient-public.',
    )
    ..addMultiOption(
      'recipient-x25519-public',
      valueHelp: 'file',
      help:
          'Recipient X25519 public key JSON (from pqforge keygen) — enables '
          'hybrid ML-KEM + X25519 encryption with explicit key paths. '
          'Repeat once per --recipient-public when encrypting to several '
          'recipients.',
    );
}

/// Adds the hybrid recipient key option to a decrypt-side command. Hybrid
/// inputs are auto-detected; this only overrides where the key is found.
void addHybridDecryptOptions(ArgParser parser) {
  parser.addOption(
    'recipient-x25519-secret',
    valueHelp: 'file',
    help:
        'Recipient raw or wrapped X25519 secret key JSON for hybrid inputs. '
        'Defaults to the conventional <key-id>.x25519.secret[.wrapped].json '
        'next to --recipient-secret when the input is hybrid.',
  );
}

/// The resolved recipient set of an encrypt command: the first
/// `--recipient-public` is the primary (classic KEM-DEM or hybrid), every
/// further one becomes a `recipients[]` key-wrap entry — the payload is still
/// sealed exactly once.
class CliRecipients {
  CliRecipients({
    required this.primary,
    required this.primaryKex,
    required this.additional,
  });

  /// The primary recipient's ML-KEM public key.
  final PqExportedKey primary;

  /// The primary recipient's X25519 public key when encrypting hybrid.
  final PqExportedKey? primaryKex;

  /// Key-wrap specs for every recipient after the first.
  final List<PqRecipientSpec> additional;

  bool get hybrid => primaryKex != null;
}

/// Resolves every `--recipient-public` (and the matching X25519 keys when
/// `--hybrid`/`--recipient-x25519-public` are in play) into a [CliRecipients].
///
/// Explicit `--recipient-x25519-public` paths pair with the recipients by
/// position and must match their count; bare `--hybrid` derives each
/// conventional sibling path (`<id>.kem.public.json` →
/// `<id>.x25519.public.json`). The hybrid key is **required** for the primary
/// (it defines the envelope's key schedule) but resolved opportunistically
/// for additional recipients — their key-wrap entries fall back to
/// post-quantum-only when no X25519 key exists, mirroring the library's
/// per-entry hybrid semantics.
Future<CliRecipients> recipientsFrom(ArgResults results) async {
  final paths = results['recipient-public'] as List<String>;
  if (paths.isEmpty) {
    throw const PqForgeException('Provide at least one --recipient-public.');
  }
  final explicitKex = results['recipient-x25519-public'] as List<String>;
  final hybrid = results['hybrid'] as bool;
  if (explicitKex.isNotEmpty && explicitKex.length != paths.length) {
    throw PqForgeException(
      'Pass --recipient-x25519-public once per --recipient-public '
      '(${paths.length} recipient(s), ${explicitKex.length} X25519 key(s)).',
    );
  }

  final kems = <PqExportedKey>[];
  final kexes = <PqExportedKey?>[];
  for (var i = 0; i < paths.length; i++) {
    final kem = await readKey(paths[i]);
    requireKind(kem, PqKeyKind.kemPublic);
    kems.add(kem);
    kexes.add(
      await _kexPublicFor(
        paths[i],
        explicitKex.isEmpty ? null : explicitKex[i],
        hybrid: hybrid,
        required: i == 0,
      ),
    );
  }
  return CliRecipients(
    primary: kems.first,
    primaryKex: kexes.first,
    additional: [
      for (var i = 1; i < kems.length; i++)
        PqRecipientSpec(
          kemPublicKey: kems[i].bytes,
          kexPublicKey: kexes[i]?.bytes,
          keyId: kems[i].keyId,
        ),
    ],
  );
}

/// Resolves one recipient's X25519 public key, or null in pure-PQC mode.
///
/// With [required] (the primary recipient) a bare `--hybrid` whose
/// conventional key file is missing is an error; for additional recipients it
/// quietly resolves to null (a post-quantum-only key-wrap entry).
Future<PqExportedKey?> _kexPublicFor(
  String kemPath,
  String? explicitPath, {
  required bool hybrid,
  required bool required,
}) async {
  String path;
  if (explicitPath != null) {
    path = explicitPath;
  } else if (hybrid) {
    if (!kemPath.contains('.kem.public')) {
      if (!required) return null;
      throw PqForgeException(
        '--hybrid could not derive an X25519 key path from $kemPath; '
        'pass --recipient-x25519-public explicitly.',
      );
    }
    path = kemPath.replaceFirst('.kem.public', '.x25519.public');
    if (!File(path).existsSync()) {
      if (!required) return null;
      throw PqForgeException(
        '--hybrid expected an X25519 public key at $path (generate one with '
        'pqforge keygen, or pass --recipient-x25519-public explicitly).',
      );
    }
  } else {
    return null;
  }
  final key = await readKey(path);
  requireKind(key, classicalKexPublicKind);
  requireX25519Key(key);
  return key;
}

/// Resolves the decrypt-side hybrid X25519 secret key.
///
/// An explicit `--recipient-x25519-secret` wins; otherwise the conventional
/// sibling of `--recipient-secret` is tried (`.kem.secret` → `.x25519.secret`,
/// in both wrapped and raw spellings). With [hybridInput] the input is known
/// to be hybrid, so an unresolvable key fails with guidance — **unless**
/// [discover] is also set (folder trees where hybrid-ness varies per file, or
/// multi-recipient inputs where this key may be an additional recipient whose
/// wrap entry needs no X25519 at all): then a missing key resolves to null
/// and the library decides, with its own descriptive error when the key
/// really was required.
Future<PqExportedKey?> hybridKexSecretFrom(
  ArgResults results,
  String? passphrase, {
  required bool hybridInput,
  bool discover = false,
}) async {
  final explicit = results['recipient-x25519-secret'] as String?;
  if (explicit == null && !hybridInput && !discover) return null;
  String? path = explicit;
  if (path == null) {
    final recipientPath = results['recipient-secret'] as String;
    final candidate = recipientPath.replaceFirst(
      '.kem.secret',
      '.x25519.secret',
    );
    for (final variant in [
      candidate,
      candidate.endsWith('.wrapped.json')
          ? candidate.replaceFirst('.wrapped.json', '.json')
          : candidate.replaceFirst(RegExp(r'\.json$'), '.wrapped.json'),
    ]) {
      if (variant != recipientPath && File(variant).existsSync()) {
        path = variant;
        break;
      }
    }
    if (path == null) {
      if (!hybridInput || discover) return null;
      throw PqForgeException(
        'This input uses hybrid ML-KEM + X25519 encryption. No X25519 secret '
        'key found next to $recipientPath; pass --recipient-x25519-secret.',
      );
    }
  }
  final key = await readKey(path, passphrase: passphrase);
  requireKind(key, classicalKexSecretKind);
  requireX25519Key(key);
  return key;
}

/// Asserts an already kind-checked classical key is specifically X25519.
void requireX25519Key(PqExportedKey key) {
  if (key.algorithmId != PqClassicalKeyAgreementAlgorithm.x25519.id) {
    throw PqForgeException('Expected an x25519 key, got ${key.algorithmId}.');
  }
}

/// Resolves `--engine` into an engine provider (default: the fast one).
PqForgeEngineProvider engineFrom(ArgResults results) =>
    switch (results['engine'] as String? ?? 'cryptography') {
      'pure-dart' => PqForgeEngineProvider.pureDart,
      _ => PqForgeEngineProvider.nativeCryptography,
    };

/// Adds the mutually exclusive passphrase sources used to wrap/unwrap secrets.
void addPassphraseOptions(ArgParser parser) {
  parser
    ..addOption(
      'passphrase-env',
      help: 'Environment variable holding the wrapping passphrase (preferred).',
      valueHelp: 'NAME',
    )
    ..addOption(
      'passphrase-file',
      help: 'File holding the wrapping passphrase (trailing newline trimmed).',
      valueHelp: 'path',
    )
    ..addOption(
      'passphrase',
      help:
          'Inline wrapping passphrase. Testing only — leaks via shell history.',
      valueHelp: 'value',
    );
}

// --- key I/O ---------------------------------------------------------------

/// Reads a [PqExportedKey] from [path], transparently unwrapping a wrapped
/// secret key when [passphrase] is supplied.
Future<PqExportedKey> readKey(String path, {String? passphrase}) async {
  final json = await readJsonMap(File(path));
  if (json.containsKey('ciphertext') && json.containsKey('kdf')) {
    if (passphrase == null) {
      throw PqForgeException(
        'Passphrase required to unwrap $path; use --passphrase-env, '
        '--passphrase-file, or --passphrase.',
      );
    }
    return const PqForge().unwrapKeyWithPassphrase(
      PqWrappedKey.fromJson(json),
      passphrase,
    );
  }
  return PqExportedKey.fromJson(json);
}

/// Reads the optional `--signer-secret` ML-DSA key, validating its kind.
Future<PqExportedKey?> optionalSignerSecret(
  ArgResults results,
  String? passphrase,
) async {
  final signerPath = results['signer-secret'] as String?;
  if (signerPath == null) return null;
  final signer = await readKey(signerPath, passphrase: passphrase);
  requireKind(signer, PqKeyKind.signatureSecret);
  return signer;
}

/// Reads an optional public key from [path], validating it has [kind].
Future<PqExportedKey?> optionalPublicKey(String? path, String kind) async {
  if (path == null) return null;
  final key = await readKey(path);
  requireKind(key, kind);
  return key;
}

String? signerKeyId(ArgResults results, PqExportedKey? signer) =>
    results['signer-key-id'] as String? ?? signer?.keyId;

void requireKind(PqExportedKey key, String kind) {
  if (key.kind != kind) {
    throw PqForgeException('Expected a $kind key, got ${key.kind}.');
  }
}

// --- passphrase resolution -------------------------------------------------

/// Resolves at most one passphrase source into the secret string, or null.
Future<String?> passphraseFrom(ArgResults results) async {
  final direct = results['passphrase'] as String?;
  final envName = results['passphrase-env'] as String?;
  final filePath = results['passphrase-file'] as String?;
  final count = [direct, envName, filePath].whereType<String>().length;
  if (count > 1) {
    throw const PqForgeException(
      'Use only one of --passphrase, --passphrase-env, or --passphrase-file.',
    );
  }
  if (direct != null) return direct;
  if (envName != null) {
    final value = Platform.environment[envName];
    if (value == null || value.isEmpty) {
      throw PqForgeException(
        'Environment variable $envName is empty or unset.',
      );
    }
    return value;
  }
  if (filePath != null) {
    final value = await File(filePath).readAsString();
    return value.replaceFirst(RegExp(r'\r?\n$'), '');
  }
  return null;
}

// --- JSON & envelope I/O ----------------------------------------------------

Future<Map<String, Object?>> readJsonMap(File file) async {
  return Map<String, Object?>.from(
    jsonDecode(await file.readAsString()) as Map,
  );
}

Future<void> writeJson(File file, Map<String, Object?> json) async {
  await file.parent.create(recursive: true);
  await file.writeAsString(
    '${const JsonEncoder.withIndent('  ').convert(json)}\n',
  );
}

Future<PqEnvelope> readEnvelope(File file) async =>
    // readAsBytes already yields a Uint8List; fromBinary takes zero-copy views
    // over it, so the prior fromList wrapper was a redundant copy (M2).
    PqEnvelope.fromBinary(await file.readAsBytes());

Future<void> writeEnvelope(File file, PqEnvelope envelope) async {
  await file.parent.create(recursive: true);
  await file.writeAsBytes(envelope.toBinary());
}

// --- argument helpers ------------------------------------------------------

PqForgeProfile profileFrom(ArgResults results) =>
    PqForgeProfile.byName(results['profile'] as String);

/// Resolves the effective composition profile from `--profile` plus the
/// optional independent `--kem` / `--sig` overrides (Phase 6). When either is
/// set, a custom profile is built so a strong KEM can pair with a lighter
/// signature (the bulk payload is AEAD-protected regardless of KEM strength).
/// The custom name round-trips: readers reconstruct an equivalent profile from
/// the stored kem/sig ids.
PqForgeProfile resolveProfile(ArgResults results) {
  final base = PqForgeProfile.byName(results['profile'] as String);
  final kemName = results['kem'] as String?;
  final sigName = results['sig'] as String?;
  if (kemName == null && sigName == null) return base;
  final kem = kemName == null ? base.kem : PqForgeProfile.byName(kemName).kem;
  final signature = sigName == null
      ? base.signature
      : PqForgeProfile.byName(sigName).signature;
  return PqForgeProfile(
    name: 'custom-${kem.id}-${signature.id}',
    kem: kem,
    signature: signature,
  );
}

Uint8List? optionalAad(ArgResults results) {
  final aad = results['aad'] as String?;
  return aad == null ? null : PqBytes.utf8Bytes(aad);
}

Uint8List? optionalContext(ArgResults results) {
  final context = results['context'] as String?;
  return context == null ? null : PqBytes.utf8Bytes(context);
}

/// Asserts an already kind-checked classical key is specifically ECDSA-P256.
void requireEcdsaKey(PqExportedKey key) {
  if (key.algorithmId != PqClassicalSignatureAlgorithm.ecdsaP256.id) {
    throw PqForgeException(
      'Expected an ecdsa-p256 key, got ${key.algorithmId}.',
    );
  }
}

/// Resolves `--text` or `--in` text input, returning the text and a default id.
Future<(String, String)> readTextInput(ArgResults results) async {
  final text = results['text'] as String?;
  final input = results['in'] as String?;
  if (text == null && input == null) {
    throw const PqForgeException('Provide --text or --in.');
  }
  if (text != null && input != null) {
    throw const PqForgeException('Use only one of --text or --in.');
  }
  if (text != null) return (text, 'inline-text');
  final file = File(input!);
  return (await file.readAsString(), file.uri.pathSegments.last);
}

// --- filesystem ------------------------------------------------------------

Future<List<File>> listFiles(Directory directory) async {
  final files = <File>[];
  await for (final entity in directory.list(
    recursive: true,
    followLinks: false,
  )) {
    if (entity is File) files.add(entity);
  }
  files.sort((a, b) => a.path.compareTo(b.path));
  return files;
}

// --- bounded concurrency ----------------------------------------------------

/// A counting semaphore that bounds how many async tasks run at once.
///
/// Folder commands run one file per background isolate (Axis B) gated by this,
/// so at most [_permits] isolates exist at any moment regardless of tree size.
/// Every [acquire] must be paired with exactly one [release].
class Semaphore {
  Semaphore(this._permits) : assert(_permits > 0, 'permits must be positive');

  int _permits;
  final _waiters = <Completer<void>>[];

  Future<void> acquire() {
    if (_permits > 0) {
      _permits--;
      return Future<void>.value();
    }
    final completer = Completer<void>();
    _waiters.add(completer);
    return completer.future;
  }

  void release() {
    if (_waiters.isNotEmpty) {
      _waiters.removeAt(0).complete();
    } else {
      _permits++;
    }
  }
}

/// Resolves the folder-processing concurrency: an explicit `--concurrency`,
/// else the CPU count capped at 8. Always at least 1.
int concurrencyFrom(ArgResults results) {
  final explicit = int.tryParse((results['concurrency'] as String?) ?? '');
  final value = explicit ?? Platform.numberOfProcessors.clamp(1, 8);
  return value < 1 ? 1 : value;
}

String safeRelativePath(Directory root, File file) {
  final rootPath = _directoryPrefix(root.absolute.path);
  final filePath = file.absolute.path;
  if (!filePath.startsWith(rootPath)) {
    throw PqForgeException('${file.path} is not inside ${root.path}.');
  }
  final relative = filePath
      .substring(rootPath.length)
      .split(Platform.pathSeparator)
      .join('/');
  requireSafeRelativePath(relative);
  return relative;
}

String _directoryPrefix(String path) => path.endsWith(Platform.pathSeparator)
    ? path
    : '$path${Platform.pathSeparator}';

void requireSafeRelativePath(String relativePath) {
  final segments = relativePath.split('/');
  if (relativePath.isEmpty ||
      relativePath.startsWith('/') ||
      relativePath.contains(r'\') ||
      segments.any(
        (segment) => segment.isEmpty || segment == '.' || segment == '..',
      )) {
    throw PqForgeException('Unsafe relative path: $relativePath');
  }
}

String joinPath(String root, String relativePath) {
  final base = root.endsWith('/') ? root.substring(0, root.length - 1) : root;
  return '$base/$relativePath';
}

// --- formatting ------------------------------------------------------------

Map<String, Object?> signatureJson({
  required String kind,
  required PqSignatureAlgorithm algorithm,
  required Uint8List signature,
  required Map<String, Object?> extra,
}) {
  return {
    'version': 1,
    'kind': kind,
    ...extra,
    'signatureAlgorithm': algorithm.id,
    'signature': base64Encode(signature),
  };
}

String guessMimeType(String path) {
  final lower = path.toLowerCase();
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.gif')) return 'image/gif';
  if (lower.endsWith('.webp')) return 'image/webp';
  if (lower.endsWith('.mp4')) return 'video/mp4';
  if (lower.endsWith('.mov')) return 'video/quicktime';
  if (lower.endsWith('.mp3')) return 'audio/mpeg';
  if (lower.endsWith('.wav')) return 'audio/wav';
  if (lower.endsWith('.pdf')) return 'application/pdf';
  if (lower.endsWith('.txt')) return 'text/plain';
  return 'application/octet-stream';
}

PqForgeProfile profileForSignature(PqSignatureAlgorithm algorithm) {
  return switch (algorithm) {
    PqSignatureAlgorithm.mlDsa44 => PqForgeProfile.compact,
    PqSignatureAlgorithm.mlDsa65 => PqForgeProfile.balanced,
    PqSignatureAlgorithm.mlDsa87 => PqForgeProfile.maximum,
  };
}

/// One-line description of the key-establishment → KDF → AEAD combination in
/// effect, e.g. `ML-KEM-1024 + X25519 → HKDF-SHA512 → AES-256-GCM`.
String suiteLabel(
  PqForgeProfile profile, {
  required bool hybrid,
  PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
}) {
  final kem = hybrid ? '${profile.kem.name} + X25519' : profile.kem.name;
  final kdf = hybrid
      ? 'HKDF-${PqHybridKemDem.combinerProfileFor(profile.kem).digestName}'
      : 'HKDF-SHA-256';
  return '$kem → $kdf → ${suite.displayName}';
}

// --- digest (pre-hashed) signing --------------------------------------------

/// Canonical message for digest-mode (pre-hashed) signing: the streamed
/// SHA-256 of the artifact under a domain-separation label, so a 32-byte file
/// signed raw can never collide with another file signed by digest.
Uint8List digestSigningMessage(Uint8List sha256) => PqBytes.lengthPrefixed([
  PqBytes.utf8Bytes('pqforge/digest-input/sha-256/v1'),
  sha256,
]);

/// Hashes [file] in O(1) memory (streamed SHA-256) and wraps the digest as
/// the canonical digest-mode signing message — gigabyte-scale artifacts never
/// touch RAM whole.
Future<Uint8List> digestMessageOfFile(File file) async =>
    digestSigningMessage(await PqBytes.sha256OfStream(file.openRead()));

/// Human-readable engine descriptor for suite detail lines.
String engineLabel(PqForgeEngineProvider provider) => switch (provider) {
  PqForgeEngineProvider.nativeCryptography => 'cryptography (hardware-capable)',
  PqForgeEngineProvider.pureDart => 'pure-dart (PointyCastle)',
};

extension DirectoryChild on Directory {
  File child(String name) =>
      File('${path.endsWith('/') ? path : '$path/'}$name');
}
