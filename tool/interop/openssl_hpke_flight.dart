/// OpenSSL `OSSL_HPKE` interop for the two KEMs BoringSSL does not export.
///
/// Both directions, all four modes, over DHKEM(X448, HKDF-SHA512) and
/// DHKEM(P-521, HKDF-SHA512). Key-schedule KDFs are HKDF-SHA256 and
/// HKDF-SHA512. AEADs are AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
/// `ephemeralIkm` is the RFC 9180 ikm, which is what `OSSL_HPKE_CTX_set1_ikme`
/// takes. A PSK id is ASCII: this OpenSSL call takes a C string.
///
/// Skips unless a pinned OpenSSL build is present, unless
/// `REQUIRE_PINNED_TLS=1`, in which case a missing build is a failure.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

Future<void> main() async {
  final ran = await runOpenSslHpkeFlight(
    required: Platform.environment['REQUIRE_PINNED_TLS'] == '1',
  );
  if (!ran && Platform.environment['REQUIRE_PINNED_TLS'] == '1') {
    exitCode = 1;
  }
}

/// Compiles [openssl_hpke_peer.c] against the pinned OpenSSL and checks it.
///
/// Returns false when the pin is absent and the flight is not required.
Future<bool> runOpenSslHpkeFlight({bool required = false}) async {
  final located = _locate();
  if (located == null) {
    stdout.writeln(
      required
          ? 'FAIL: pinned OpenSSL libcrypto was not found'
          : 'SKIP: pinned OpenSSL build not present',
    );
    return false;
  }
  final outDir = Directory('${Directory.current.path}/tool/interop/.build');
  outDir.createSync(recursive: true);
  final peer = '${outDir.path}/openssl_hpke_peer';
  final compile = Process.runSync('cc', [
    '-O2',
    '-o',
    peer,
    'tool/interop/openssl_hpke_peer.c',
    '-I${located.include}',
    located.libcrypto,
    '-pthread',
    '-ldl',
  ]);
  if (compile.exitCode != 0) {
    stderr
      ..writeln(compile.stdout)
      ..writeln(compile.stderr);
    throw StateError('failed to link openssl_hpke_peer');
  }

  const info = 'hpke info';
  const aad = 'hpke aad';
  const plaintext = 'record sealed to a wide kem';
  const exportContext = 'session';
  const pskId = 'wide-psk';
  final ikmR = Uint8List.fromList(List<int>.generate(66, (i) => i + 1));
  final ikmE = Uint8List.fromList(List<int>.generate(66, (i) => 80 + (i % 40)));
  final ikmS = Uint8List.fromList(List<int>.generate(66, (i) => 200 - i));
  final psk = Uint8List.fromList(List<int>.generate(32, (i) => 9 + i));

  for (final kem in ['x448', 'p521']) {
    for (final kdf in ['sha256', 'sha512']) {
      await _deriveAgrees(peer, kem, ikmR);
      for (final aead in ['aes128', 'aes256', 'chacha']) {
        for (final mode in ['base', 'psk', 'auth', 'authpsk']) {
          await _bothDirections(
            peer,
            mode: mode,
            kem: kem,
            kdf: kdf,
            aead: aead,
            ikmR: ikmR,
            ikmE: ikmE,
            ikmS: ikmS,
            psk: psk,
            pskId: pskId,
            info: info,
            aad: aad,
            plaintext: plaintext,
            exportContext: exportContext,
          );
        }
      }
    }
  }
  stdout.writeln(
    'OpenSSL HPKE interop: base, PSK, auth, and authPSK, X448 and P-521, '
    'HKDF-SHA256/512, AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.',
  );
  return true;
}

Future<void> _deriveAgrees(String peer, String kem, Uint8List ikm) async {
  final ours = await PqHpke.deriveKeyPair(kem: _kem(kem), ikm: ikm);
  final line = _run(peer, ['derive', kem, 'sha512', _toHex(ikm)]);
  if (line != _toHex(ours.publicKey)) {
    throw StateError(
      'DeriveKeyPair public key disagrees with OpenSSL for $kem\n'
      'ours ${_toHex(ours.publicKey)}\n'
      'openssl $line',
    );
  }
}

Future<void> _bothDirections(
  String peer, {
  required String mode,
  required String kem,
  required String kdf,
  required String aead,
  required Uint8List ikmR,
  required Uint8List ikmE,
  required Uint8List ikmS,
  required Uint8List psk,
  required String pskId,
  required String info,
  required String aad,
  required String plaintext,
  required String exportContext,
}) async {
  final hpkeMode = switch (mode) {
    'base' => HpkeMode.base,
    'psk' => HpkeMode.psk,
    'auth' => HpkeMode.auth,
    'authpsk' => HpkeMode.authPsk,
    _ => throw ArgumentError(mode),
  };
  final suite = HpkeSuite(kem: _kem(kem), kdf: _kdf(kdf), aead: _aead(aead));
  final recipient = await PqHpke.deriveKeyPair(kem: suite.kem, ikm: ikmR);
  final sender = hpkeMode.usesAuth
      ? await PqHpke.deriveKeyPair(kem: suite.kem, ikm: ikmS)
      : null;
  final infoBytes = Uint8List.fromList(info.codeUnits);
  final aadBytes = Uint8List.fromList(aad.codeUnits);
  final ptBytes = Uint8List.fromList(plaintext.codeUnits);
  final expBytes = Uint8List.fromList(exportContext.codeUnits);
  final pskBytes = hpkeMode.usesPsk ? psk : null;
  final pskIdBytes = hpkeMode.usesPsk
      ? Uint8List.fromList(pskId.codeUnits)
      : null;
  final setup = await PqHpke.setupSender(
    suite: suite,
    mode: hpkeMode,
    recipientPublicKey: recipient.publicKey,
    info: infoBytes,
    psk: pskBytes,
    pskId: pskIdBytes,
    senderKey: sender,
    ephemeralIkm: ikmE,
  );
  final ct = setup.context.seal(ptBytes, aad: aadBytes);
  final exported = setup.context.export(expBytes, 32);
  final label = '$mode $kem/$kdf/$aead';

  final opened = _run(peer, [
    'open',
    mode,
    kem,
    kdf,
    aead,
    _toHex(ikmR),
    _toHex(setup.enc),
    _toHex(infoBytes),
    _toHex(aadBytes),
    _toHex(ct),
    _toHex(expBytes),
    '32',
    _optHex(pskBytes),
    _optHex(pskIdBytes),
    _optHex(sender?.publicKey),
  ]);
  final openedParts = opened.split(' ');
  if (openedParts.length != 2 ||
      openedParts[0] != _toHex(ptBytes) ||
      openedParts[1] != _toHex(exported)) {
    throw StateError('OpenSSL did not open a pqforge $label seal: $opened');
  }

  final sealed = _run(peer, [
    'seal',
    mode,
    kem,
    kdf,
    aead,
    _toHex(recipient.publicKey),
    _toHex(infoBytes),
    _toHex(aadBytes),
    _toHex(ptBytes),
    _toHex(expBytes),
    '32',
    _toHex(ikmE),
    _optHex(pskBytes),
    _optHex(pskIdBytes),
    _optHex(hpkeMode.usesAuth ? ikmS : null),
  ]);
  final sealedParts = sealed.split(' ');
  if (sealedParts.length != 3) {
    throw StateError('OpenSSL seal output "$sealed"');
  }
  if (sealedParts[0] != _toHex(setup.enc) || sealedParts[1] != _toHex(ct)) {
    throw StateError(
      'OpenSSL seal disagrees for $label\n'
      'enc ${sealedParts[0]} vs ${_toHex(setup.enc)}',
    );
  }
  final fromPeer = await PqHpke.open(
    suite: suite,
    mode: hpkeMode,
    enc: _hex(sealedParts[0]),
    ciphertext: _hex(sealedParts[1]),
    recipientKey: recipient,
    info: infoBytes,
    aad: aadBytes,
    psk: pskBytes,
    pskId: pskIdBytes,
    senderPublicKey: sender?.publicKey,
  );
  if (!_same(fromPeer.plaintext, ptBytes)) {
    throw StateError('pqforge did not open an OpenSSL $label seal');
  }
  if (!_same(fromPeer.context.export(expBytes, 32), _hex(sealedParts[2]))) {
    throw StateError('exporter disagrees for $label');
  }
  setup.context.dispose();
  fromPeer.context.dispose();
}

HpkeKem _kem(String name) => switch (name) {
  'x448' => HpkeKem.x448HkdfSha512,
  'p521' => HpkeKem.p521HkdfSha512,
  _ => throw ArgumentError(name),
};

HpkeKdf _kdf(String name) => switch (name) {
  'sha256' => HpkeKdf.hkdfSha256,
  'sha512' => HpkeKdf.hkdfSha512,
  _ => throw ArgumentError(name),
};

HpkeAead _aead(String name) => switch (name) {
  'aes128' => HpkeAead.aes128Gcm,
  'aes256' => HpkeAead.aes256Gcm,
  'chacha' => HpkeAead.chacha20Poly1305,
  _ => throw ArgumentError(name),
};

({String prefix, String include, String libcrypto})? _locate() {
  final roots = <String>[
    if (Platform.environment['OPENSSL_HPKE_PREFIX'] != null)
      Platform.environment['OPENSSL_HPKE_PREFIX']!,
    if (Platform.environment['PINNED_TLS_PREFIX'] != null)
      '${Platform.environment['PINNED_TLS_PREFIX']}/openssl',
    '${Directory.current.path}/tool/interop/.build/openssl',
  ];
  for (final root in roots) {
    final include = '$root/include';
    if (!File('$include/openssl/hpke.h').existsSync()) continue;
    for (final name in ['libcrypto.a', 'libcrypto.so']) {
      final lib = '$root/lib/$name';
      if (File(lib).existsSync()) {
        return (prefix: root, include: include, libcrypto: lib);
      }
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

String _optHex(Uint8List? bytes) => bytes == null ? '-' : _toHex(bytes);

String _toHex(Uint8List bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.isEmpty ? '-' : buffer.toString();
}

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
