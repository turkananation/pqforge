import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqRsa', () {
    late Uint8List modulus;
    late Uint8List exponent;
    late PqRsaPrivateKey privateKey;

    setUpAll(() {
      final kp = PqRsa.generateKeyPair();
      modulus = kp.modulus;
      exponent = kp.exponent;
      privateKey = kp.privateKey;
    });

    test('PKCS#1 SHA-256 round-trips and rejects a flipped signature', () {
      final message = Uint8List.fromList('rsa pkcs1'.codeUnits);
      final signature = PqRsa.signPkcs1(
        privateKey: privateKey,
        message: message,
        hash: PqRsaHash.sha256,
      );
      expect(signature, hasLength(256));
      expect(
        PqRsa.verifyPkcs1(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: signature,
          hash: PqRsaHash.sha256,
        ),
        isTrue,
      );
      final flipped = Uint8List.fromList(signature)..[0] ^= 1;
      expect(
        PqRsa.verifyPkcs1(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: flipped,
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });

    test('PSS SHA-256 round-trips', () {
      final message = Uint8List.fromList('rsa pss'.codeUnits);
      final signature = PqRsa.signPss(
        privateKey: privateKey,
        message: message,
        hash: PqRsaHash.sha256,
      );
      expect(
        PqRsa.verifyPss(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: signature,
          hash: PqRsaHash.sha256,
        ),
        isTrue,
      );
      expect(
        PqRsa.verifyPss(
          modulus: modulus,
          exponent: exponent,
          message: Uint8List.fromList('other'.codeUnits),
          signature: signature,
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });

    test('a 1024-bit claim and exponent 1 do not verify', () {
      expect(
        PqRsa.verifyPkcs1(
          modulus: Uint8List(128),
          exponent: Uint8List.fromList([1, 0, 1]),
          message: Uint8List(1),
          signature: Uint8List(128),
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
      expect(
        PqRsa.verifyPkcs1(
          modulus: modulus,
          exponent: Uint8List.fromList([1]),
          message: Uint8List(1),
          signature: Uint8List(256),
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });

    test('PSS accepts a salt length other than the hash length', () {
      final message = Uint8List.fromList('salt 20'.codeUnits);
      final signature = PqRsa.signPss(
        privateKey: privateKey,
        message: message,
        hash: PqRsaHash.sha256,
        saltLength: 20,
      );
      expect(
        PqRsa.verifyPss(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: signature,
          hash: PqRsaHash.sha256,
          saltLength: 20,
        ),
        isTrue,
      );
      expect(
        PqRsa.verifyPss(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: signature,
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });

    test('refuses a generated modulus outside 2048, 3072, and 4096', () {
      expect(
        () => PqRsa.generateKeyPair(modulusBits: 1024),
        throwsArgumentError,
      );
      expect(
        () => PqRsa.generateKeyPair(modulusBits: 512),
        throwsArgumentError,
      );
      expect(
        () => PqRsa.generateKeyPair(modulusBits: 8192),
        throwsArgumentError,
      );
    });

    test('refuses a 512-bit and an 8192-bit verify', () {
      expect(
        PqRsa.verifyPkcs1(
          modulus: Uint8List(64),
          exponent: Uint8List.fromList([1, 0, 1]),
          message: Uint8List(1),
          signature: Uint8List(64),
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
      expect(
        PqRsa.verifyPkcs1(
          modulus: Uint8List(1024),
          exponent: Uint8List.fromList([1, 0, 1]),
          message: Uint8List(1),
          signature: Uint8List(1024),
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });
  });

  for (final bits in const [1024, 2048, 3072, 4096]) {
    group('RSA $bits', () {
      late Uint8List modulus;
      late Uint8List exponent;
      late PqRsaPrivateKey privateKey;

      setUpAll(() {
        final kp = bits == 1024
            ? _rsa1024()
            : PqRsa.generateKeyPair(modulusBits: bits);
        modulus = kp.modulus;
        exponent = kp.exponent;
        privateKey = kp.privateKey;
      });

      for (final hash in PqRsaHash.values) {
        test('PKCS#1 ${hash.name} verifies and rejects a flipped byte', () {
          final message = Uint8List.fromList(
            'pkcs1 $bits ${hash.name}'.codeUnits,
          );
          final signature = PqRsa.signPkcs1(
            privateKey: privateKey,
            message: message,
            hash: hash,
          );
          expect(signature, hasLength(bits ~/ 8));
          expect(
            PqRsa.verifyPkcs1(
              modulus: modulus,
              exponent: exponent,
              message: message,
              signature: signature,
              hash: hash,
            ),
            isTrue,
          );
          final flipped = Uint8List.fromList(signature)..[0] ^= 1;
          expect(
            PqRsa.verifyPkcs1(
              modulus: modulus,
              exponent: exponent,
              message: message,
              signature: flipped,
              hash: hash,
            ),
            isFalse,
          );
          expect(
            PqRsa.verifyPkcs1(
              modulus: modulus,
              exponent: exponent,
              message: Uint8List.fromList('other'.codeUnits),
              signature: signature,
              hash: hash,
            ),
            isFalse,
          );
        });

        test('PSS ${hash.name} verifies and rejects a flipped byte', () {
          final message = Uint8List.fromList(
            'pss $bits ${hash.name}'.codeUnits,
          );
          final tooSmall = bits ~/ 8 < hash.digestBytes * 2 + 2;
          if (tooSmall) {
            expect(
              () => PqRsa.signPss(
                privateKey: privateKey,
                message: message,
                hash: hash,
              ),
              throwsArgumentError,
            );
            expect(
              PqRsa.verifyPss(
                modulus: modulus,
                exponent: exponent,
                message: message,
                signature: Uint8List(bits ~/ 8),
                hash: hash,
              ),
              isFalse,
            );
            return;
          }
          final signature = PqRsa.signPss(
            privateKey: privateKey,
            message: message,
            hash: hash,
          );
          expect(
            PqRsa.verifyPss(
              modulus: modulus,
              exponent: exponent,
              message: message,
              signature: signature,
              hash: hash,
            ),
            isTrue,
          );
          final flipped = Uint8List.fromList(signature)..[0] ^= 1;
          expect(
            PqRsa.verifyPss(
              modulus: modulus,
              exponent: exponent,
              message: message,
              signature: flipped,
              hash: hash,
            ),
            isFalse,
          );
        });
      }
    });
  }

  test('OpenSSL PKCS#1 and PSS match every hash', () {
    final version = Process.runSync('openssl', ['version']);
    if (version.exitCode != 0) {
      markTestSkipped('openssl is not on PATH');
    }
    final dir = Directory.systemTemp.createTempSync('pqforge-rsa-');
    try {
      final pem = _opensslKey(dir, 2048);
      final key = _opensslPrivateKey(pem);
      final message = Uint8List.fromList('openssl rsa'.codeUnits);
      final msg = File('${dir.path}/msg')..writeAsBytesSync(message);
      for (final hash in PqRsaHash.values) {
        final pkcs1 = PqRsa.signPkcs1(
          privateKey: key.privateKey,
          message: message,
          hash: hash,
        );
        final opensslPkcs1 = _opensslPkeyutl(
          pem: pem,
          message: msg.path,
          digest: hash.name,
          padding: 'pkcs1',
          signatureOut: '${dir.path}/${hash.name}.pkcs1.sig',
        );
        expect(opensslPkcs1, orderedEquals(pkcs1), reason: hash.name);
        expect(
          PqRsa.verifyPkcs1(
            modulus: key.modulus,
            exponent: key.exponent,
            message: message,
            signature: opensslPkcs1,
            hash: hash,
          ),
          isTrue,
          reason: hash.name,
        );
        _opensslPkeyutl(
          pem: pem,
          message: msg.path,
          digest: hash.name,
          padding: 'pkcs1',
          signatureIn: '${dir.path}/${hash.name}.pkcs1.ours',
          ours: pkcs1,
        );

        final pss = PqRsa.signPss(
          privateKey: key.privateKey,
          message: message,
          hash: hash,
        );
        _opensslPkeyutl(
          pem: pem,
          message: msg.path,
          digest: hash.name,
          padding: 'pss',
          signatureIn: '${dir.path}/${hash.name}.pss.ours',
          ours: pss,
        );
        final opensslPss = _opensslPkeyutl(
          pem: pem,
          message: msg.path,
          digest: hash.name,
          padding: 'pss',
          signatureOut: '${dir.path}/${hash.name}.pss.sig',
        );
        expect(
          PqRsa.verifyPss(
            modulus: key.modulus,
            exponent: key.exponent,
            message: message,
            signature: opensslPss,
            hash: hash,
          ),
          isTrue,
          reason: hash.name,
        );
      }

      final smallPem = _opensslKey(dir, 1024);
      final small = _opensslPrivateKey(smallPem);
      final sha224 = PqRsa.signPss(
        privateKey: small.privateKey,
        message: message,
        hash: PqRsaHash.sha224,
      );
      _opensslPkeyutl(
        pem: smallPem,
        message: msg.path,
        digest: 'sha224',
        padding: 'pss',
        signatureIn: '${dir.path}/sha224-1024.ours',
        ours: sha224,
      );
      final opensslSha224 = _opensslPkeyutl(
        pem: smallPem,
        message: msg.path,
        digest: 'sha224',
        padding: 'pss',
        signatureOut: '${dir.path}/sha224-1024.sig',
      );
      expect(
        PqRsa.verifyPss(
          modulus: small.modulus,
          exponent: small.exponent,
          message: message,
          signature: opensslSha224,
          hash: PqRsaHash.sha224,
        ),
        isTrue,
      );
      final refused = Process.runSync('openssl', [
        'pkeyutl',
        '-sign',
        '-inkey',
        smallPem,
        '-rawin',
        '-in',
        msg.path,
        '-digest',
        'sha512',
        '-pkeyopt',
        'rsa_padding_mode:pss',
        '-pkeyopt',
        'rsa_pss_saltlen:digest',
        '-pkeyopt',
        'rsa_mgf1_md:sha512',
      ]);
      expect(refused.exitCode, isNonZero);
      expect(
        () => PqRsa.signPss(
          privateKey: small.privateKey,
          message: message,
          hash: PqRsaHash.sha512,
        ),
        throwsArgumentError,
      );
    } finally {
      dir.deleteSync(recursive: true);
    }
  });
}

({PqRsaPrivateKey privateKey, Uint8List modulus, Uint8List exponent})
_rsa1024() {
  final fortuna = pc.FortunaRandom();
  final random = Random.secure();
  final seed = Uint8List(32);
  for (var i = 0; i < seed.length; i++) {
    seed[i] = random.nextInt(256);
  }
  fortuna.seed(pc.KeyParameter(seed));
  final generator = pc.RSAKeyGenerator()
    ..init(
      pc.ParametersWithRandom(
        pc.RSAKeyGeneratorParameters(BigInt.from(65537), 1024, 64),
        fortuna,
      ),
    );
  final pair = generator.generateKeyPair();
  final publicKey = pair.publicKey;
  final privateKey = pair.privateKey;
  final modulus = _fixed(publicKey.modulus!, 128);
  final exponent = _minimal(publicKey.exponent!);
  return (
    modulus: modulus,
    exponent: exponent,
    privateKey: PqRsaPrivateKey(
      modulus: modulus,
      privateExponent: _minimal(privateKey.privateExponent!),
      prime1: _minimal(privateKey.p!),
      prime2: _minimal(privateKey.q!),
      publicExponent: exponent,
    ),
  );
}

Uint8List _minimal(BigInt value) {
  if (value == BigInt.zero) return Uint8List(1);
  return _fixed(value, (value.bitLength + 7) >> 3);
}

Uint8List _fixed(BigInt value, int length) {
  final out = Uint8List(length);
  final mask = BigInt.from(0xff);
  var remaining = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (remaining & mask).toInt();
    remaining >>= 8;
  }
  return out;
}

String _opensslKey(Directory dir, int bits) {
  final pem = '${dir.path}/rsa$bits.pem';
  final result = Process.runSync('openssl', [
    'genpkey',
    '-algorithm',
    'RSA',
    '-pkeyopt',
    'rsa_keygen_bits:$bits',
    '-out',
    pem,
  ]);
  expect(result.exitCode, 0, reason: '${result.stderr}');
  return pem;
}

({PqRsaPrivateKey privateKey, Uint8List modulus, Uint8List exponent})
_opensslPrivateKey(String pem) {
  final text = Process.runSync('openssl', [
    'pkey',
    '-in',
    pem,
    '-text',
    '-noout',
  ]);
  expect(text.exitCode, 0, reason: '${text.stderr}');
  final fields = _opensslFields(text.stdout as String);
  final modulus = fields['modulus']!;
  final exponent = fields['publicExponent']!;
  return (
    modulus: modulus,
    exponent: exponent,
    privateKey: PqRsaPrivateKey(
      modulus: modulus,
      privateExponent: fields['privateExponent']!,
      prime1: fields['prime1']!,
      prime2: fields['prime2']!,
      publicExponent: exponent,
    ),
  );
}

Uint8List _opensslPkeyutl({
  required String pem,
  required String message,
  required String digest,
  required String padding,
  String? signatureOut,
  String? signatureIn,
  Uint8List? ours,
}) {
  final args = <String>[
    'pkeyutl',
    if (signatureOut != null) '-sign' else '-verify',
    '-inkey',
    pem,
    '-rawin',
    '-in',
    message,
    '-digest',
    digest,
    '-pkeyopt',
    'rsa_padding_mode:$padding',
    if (padding == 'pss') ...[
      '-pkeyopt',
      'rsa_pss_saltlen:digest',
      '-pkeyopt',
      'rsa_mgf1_md:$digest',
    ],
  ];
  if (signatureOut != null) {
    args.addAll(['-out', signatureOut]);
  } else {
    File(signatureIn!).writeAsBytesSync(ours!);
    args.addAll(['-sigfile', signatureIn]);
  }
  final result = Process.runSync('openssl', args);
  expect(result.exitCode, 0, reason: '$digest $padding ${result.stderr}');
  if (signatureOut == null) return ours!;
  return File(signatureOut).readAsBytesSync();
}

Map<String, Uint8List> _opensslFields(String text) {
  final out = <String, Uint8List>{};
  final hex = StringBuffer();
  String? section;

  void flush() {
    if (section == null || hex.isEmpty) {
      hex.clear();
      return;
    }
    final raw = hex.toString();
    hex.clear();
    out[section] = _parseHex(raw);
  }

  for (final rawLine in text.split('\n')) {
    final line = rawLine.trim();
    final exponent = RegExp(
      r'^publicExponent:.*\(0x([0-9a-fA-F]+)\)$',
    ).firstMatch(line);
    if (exponent != null) {
      flush();
      section = null;
      var value = exponent.group(1)!;
      if (value.length.isOdd) value = '0$value';
      out['publicExponent'] = _parseHex(value);
      continue;
    }
    final label = RegExp(r'^([A-Za-z0-9]+):$').firstMatch(line);
    if (label != null) {
      flush();
      section = label.group(1);
      continue;
    }
    if (section != null &&
        RegExp(r'^[0-9a-f]{2}(?::[0-9a-f]{2})*:?$').hasMatch(line)) {
      hex.write(line.replaceAll(':', ''));
    }
  }
  flush();
  return out;
}

Uint8List _parseHex(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}
