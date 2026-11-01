/// BoringSSL EVP_HPKE interop for [PqHpke].
///
/// Base and auth, both directions, over DHKEM(X25519, HKDF-SHA256) and
/// DHKEM(P-256, HKDF-SHA256). KDFs are HKDF-SHA256 and HKDF-SHA384. AEADs
/// are AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305. PSK modes are not
/// here: this BoringSSL public API has no PSK setup. P-384 and HKDF-SHA512
/// are not in this pin's `hpke.h`.
///
/// Skips unless a pinned BoringSSL build is present, unless
/// `REQUIRE_PINNED_TLS=1`, in which case a missing build is a failure.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

Future<void> main() async {
  final ran = await runBoringSslHpkeFlight(
    required: Platform.environment['REQUIRE_PINNED_TLS'] == '1',
  );
  if (!ran && Platform.environment['REQUIRE_PINNED_TLS'] == '1') {
    exitCode = 1;
  }
}

/// Compiles [hpke_peer.c] against the pinned BoringSSL and checks it.
///
/// Returns false when the pin is absent and the flight is not required.
Future<bool> runBoringSslHpkeFlight({bool required = false}) async {
  final located = _locate();
  if (located == null) {
    stdout.writeln(
      required
          ? 'FAIL: pinned BoringSSL libcrypto was not found'
          : 'SKIP: pinned BoringSSL build not present',
    );
    return false;
  }
  final peer = '${located.prefix}/bin/hpke_peer';
  final compile = Process.runSync('c++', [
    '-O2',
    '-o',
    peer,
    'tool/interop/hpke_peer.c',
    '-I${located.include}',
    located.libcrypto,
    '-pthread',
  ]);
  if (compile.exitCode != 0) {
    stderr
      ..writeln(compile.stdout)
      ..writeln(compile.stderr);
    throw StateError('failed to link hpke_peer');
  }

  await _deriveAgrees(
    peer,
    'x25519',
    _hex('6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037'),
  );
  await _deriveAgrees(
    peer,
    'p256',
    _hex('4273e4d57e4e3e1b0d9e9b1c1a5e5c5d5e5f606162636465666768696a6b6c6d'),
  );

  const info = 'hpke info';
  const aad = 'hpke aad';
  const plaintext = 'record sealed to a public key';
  const exportContext = 'session';
  for (final kem in ['x25519', 'p256']) {
    for (final kdf in ['sha256', 'sha384']) {
      for (final aead in ['aes128', 'aes256', 'chacha']) {
        await _baseBothDirections(
          peer,
          kem: kem,
          kdf: kdf,
          aead: aead,
          info: info,
          aad: aad,
          plaintext: plaintext,
          exportContext: exportContext,
        );
        await _authBothDirections(
          peer,
          kem: kem,
          kdf: kdf,
          aead: aead,
          info: info,
          aad: aad,
          plaintext: plaintext,
          exportContext: exportContext,
        );
      }
    }
  }
  stdout.writeln(
    'BoringSSL HPKE interop: base and auth, X25519 and P-256, '
    'HKDF-SHA256/384, AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.',
  );
  return true;
}

Future<void> _deriveAgrees(String peer, String kem, Uint8List ikm) async {
  final ours = await PqHpke.deriveKeyPair(
    kem: kem == 'x25519' ? HpkeKem.x25519HkdfSha256 : HpkeKem.p256HkdfSha256,
    ikm: ikm,
  );
  final line = _run(peer, ['derive', kem, _toHex(ikm)]);
  final parts = line.split(' ');
  if (parts.length != 2) {
    throw StateError('derive output "$line"');
  }
  if (parts[0] != _toHex(ours.secretKey) ||
      parts[1] != _toHex(ours.publicKey)) {
    throw StateError(
      'DeriveKeyPair disagrees with BoringSSL for $kem\n'
      'ours ${_toHex(ours.secretKey)} ${_toHex(ours.publicKey)}\n'
      'bssl $line',
    );
  }
}

Future<void> _baseBothDirections(
  String peer, {
  required String kem,
  required String kdf,
  required String aead,
  required String info,
  required String aad,
  required String plaintext,
  required String exportContext,
}) async {
  final suite = _suite(kem, kdf, aead);
  final recipient = await PqHpke.generateKeyPair(suite.kem);
  final ikmE = Uint8List.fromList(List<int>.generate(32, (i) => i + 3));
  final eph = await PqHpke.deriveKeyPair(kem: suite.kem, ikm: ikmE);
  // BoringSSL's X25519 testing seed is the ephemeral private key.
  // Its P-256 testing seed is the DeriveKeyPair ikm.
  final seed = kem == 'x25519' ? eph.secretKey : ikmE;
  final setup = await PqHpke.setupSender(
    suite: suite,
    mode: HpkeMode.base,
    recipientPublicKey: recipient.publicKey,
    info: Uint8List.fromList(info.codeUnits),
    ephemeralIkm: ikmE,
  );
  final ct = setup.context.seal(
    Uint8List.fromList(plaintext.codeUnits),
    aad: Uint8List.fromList(aad.codeUnits),
  );
  final exported = setup.context.export(
    Uint8List.fromList(exportContext.codeUnits),
    32,
  );
  final opened = _run(peer, [
    'base-open',
    kem,
    kdf,
    aead,
    _toHex(recipient.secretKey),
    _toHex(setup.enc),
    _toHex(Uint8List.fromList(info.codeUnits)),
    _toHex(Uint8List.fromList(aad.codeUnits)),
    _toHex(ct),
    _toHex(Uint8List.fromList(exportContext.codeUnits)),
    '32',
  ]);
  final openedParts = opened.split(' ');
  if (openedParts[0] != _toHex(Uint8List.fromList(plaintext.codeUnits)) ||
      openedParts[1] != _toHex(exported)) {
    throw StateError('BoringSSL did not open a pqforge $kem/$kdf/$aead seal');
  }

  final sealed = _run(peer, [
    'base-seal',
    kem,
    kdf,
    aead,
    _toHex(recipient.publicKey),
    _toHex(Uint8List.fromList(info.codeUnits)),
    _toHex(Uint8List.fromList(aad.codeUnits)),
    _toHex(Uint8List.fromList(plaintext.codeUnits)),
    _toHex(Uint8List.fromList(exportContext.codeUnits)),
    '32',
    _toHex(seed),
  ]);
  final sealedParts = sealed.split(' ');
  if (sealedParts.length != 3) throw StateError('base-seal output "$sealed"');
  if (sealedParts[0] != _toHex(setup.enc) || sealedParts[1] != _toHex(ct)) {
    throw StateError(
      'BoringSSL seed seal disagrees for $kem/$kdf/$aead\n'
      'enc ${sealedParts[0]} vs ${_toHex(setup.enc)}',
    );
  }
  final fromPeer = await PqHpke.open(
    suite: suite,
    mode: HpkeMode.base,
    enc: _hex(sealedParts[0]),
    ciphertext: _hex(sealedParts[1]),
    recipientKey: recipient,
    info: Uint8List.fromList(info.codeUnits),
    aad: Uint8List.fromList(aad.codeUnits),
  );
  if (!_same(fromPeer.plaintext, Uint8List.fromList(plaintext.codeUnits))) {
    throw StateError('pqforge did not open a BoringSSL $kem/$kdf/$aead seal');
  }
  if (!_same(
    fromPeer.context.export(Uint8List.fromList(exportContext.codeUnits), 32),
    _hex(sealedParts[2]),
  )) {
    throw StateError('exporter disagrees for $kem/$kdf/$aead');
  }
  setup.context.dispose();
  fromPeer.context.dispose();
}

Future<void> _authBothDirections(
  String peer, {
  required String kem,
  required String kdf,
  required String aead,
  required String info,
  required String aad,
  required String plaintext,
  required String exportContext,
}) async {
  final suite = _suite(kem, kdf, aead);
  final recipient = await PqHpke.generateKeyPair(suite.kem);
  final sender = await PqHpke.generateKeyPair(suite.kem);
  final ikmE = Uint8List.fromList(List<int>.generate(32, (i) => 80 + i));
  final eph = await PqHpke.deriveKeyPair(kem: suite.kem, ikm: ikmE);
  final seed = kem == 'x25519' ? eph.secretKey : ikmE;
  final setup = await PqHpke.setupSender(
    suite: suite,
    mode: HpkeMode.auth,
    recipientPublicKey: recipient.publicKey,
    info: Uint8List.fromList(info.codeUnits),
    senderKey: sender,
    ephemeralIkm: ikmE,
  );
  final ct = setup.context.seal(
    Uint8List.fromList(plaintext.codeUnits),
    aad: Uint8List.fromList(aad.codeUnits),
  );
  final opened = _run(peer, [
    'auth-open',
    kem,
    kdf,
    aead,
    _toHex(recipient.secretKey),
    _toHex(sender.publicKey),
    _toHex(setup.enc),
    _toHex(Uint8List.fromList(info.codeUnits)),
    _toHex(Uint8List.fromList(aad.codeUnits)),
    _toHex(ct),
    _toHex(Uint8List.fromList(exportContext.codeUnits)),
    '32',
  ]);
  if (opened.split(' ').first !=
      _toHex(Uint8List.fromList(plaintext.codeUnits))) {
    throw StateError('BoringSSL auth-open failed for $kem/$kdf/$aead');
  }
  final sealed = _run(peer, [
    'auth-seal',
    kem,
    kdf,
    aead,
    _toHex(sender.secretKey),
    _toHex(recipient.publicKey),
    _toHex(Uint8List.fromList(info.codeUnits)),
    _toHex(Uint8List.fromList(aad.codeUnits)),
    _toHex(Uint8List.fromList(plaintext.codeUnits)),
    _toHex(Uint8List.fromList(exportContext.codeUnits)),
    '32',
    _toHex(seed),
  ]);
  final parts = sealed.split(' ');
  if (parts[0] != _toHex(setup.enc) || parts[1] != _toHex(ct)) {
    throw StateError('BoringSSL auth seed seal disagrees for $kem/$kdf/$aead');
  }
  final fromPeer = await PqHpke.open(
    suite: suite,
    mode: HpkeMode.auth,
    enc: _hex(parts[0]),
    ciphertext: _hex(parts[1]),
    recipientKey: recipient,
    info: Uint8List.fromList(info.codeUnits),
    aad: Uint8List.fromList(aad.codeUnits),
    senderPublicKey: sender.publicKey,
  );
  if (!_same(fromPeer.plaintext, Uint8List.fromList(plaintext.codeUnits))) {
    throw StateError('pqforge auth open failed for $kem/$kdf/$aead');
  }
  setup.context.dispose();
  fromPeer.context.dispose();
}

HpkeSuite _suite(String kem, String kdf, String aead) {
  return HpkeSuite(
    kem: switch (kem) {
      'x25519' => HpkeKem.x25519HkdfSha256,
      'p256' => HpkeKem.p256HkdfSha256,
      _ => throw ArgumentError(kem),
    },
    kdf: switch (kdf) {
      'sha256' => HpkeKdf.hkdfSha256,
      'sha384' => HpkeKdf.hkdfSha384,
      _ => throw ArgumentError(kdf),
    },
    aead: switch (aead) {
      'aes128' => HpkeAead.aes128Gcm,
      'aes256' => HpkeAead.aes256Gcm,
      'chacha' => HpkeAead.chacha20Poly1305,
      _ => throw ArgumentError(aead),
    },
  );
}

({String prefix, String include, String libcrypto})? _locate() {
  final roots = <String>[
    if (Platform.environment['PINNED_TLS_PREFIX'] != null)
      Platform.environment['PINNED_TLS_PREFIX']!,
    '${Directory.current.path}/tool/interop/.build',
  ];
  for (final root in roots) {
    final nestedLib = '$root/boringssl/lib/libcrypto.a';
    final nestedInc = '$root/boringssl/include';
    if (File(nestedLib).existsSync()) {
      return (
        prefix: '$root/boringssl',
        include: nestedInc,
        libcrypto: nestedLib,
      );
    }
    final flatLib = '$root/lib/libcrypto.a';
    final flatInc = '$root/include';
    if (File(flatLib).existsSync()) {
      return (prefix: root, include: flatInc, libcrypto: flatLib);
    }
  }
  return null;
}

String _run(String peer, List<String> args) {
  final result = Process.runSync(peer, args);
  if (result.exitCode != 0) {
    throw StateError(
      '${args.first} failed\n${result.stdout}\n${result.stderr}',
    );
  }
  return (result.stdout as String).trim();
}

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _toHex(Uint8List bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

bool _same(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) return false;
  }
  return true;
}
