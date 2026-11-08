import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqEd448', () {
    test('RFC 8032 test 1, empty message', () {
      _expectVector(
        secret:
            '6c82a562cb808d10d632be89c8513ebf'
            '6c929f34ddfa8c9f63c9960ef6e348a3'
            '528c8a3fcc2f044e39a3fc5b94492f8f'
            '032e7549a20098f95b',
        publicKey:
            '5fd7449b59b461fd2ce787ec616ad46a'
            '1da1342485a70e1f8a0ea75d80e96778'
            'edf124769b46c7061bd6783df1e50f6c'
            'd1fa1abeafe8256180',
        message: Uint8List(0),
        signature:
            '533a37f6bbe457251f023c0d88f976ae'
            '2dfb504a843e34d2074fd823d41a591f'
            '2b233f034f628281f2fd7a22ddd47d78'
            '28c59bd0a21bfd3980ff0d2028d4b18a'
            '9df63e006c5d1c2d345b925d8dc00b41'
            '04852db99ac5c7cdda8530a113a0f4db'
            'b61149f05a7363268c71d95808ff2e65'
            '2600',
      );
    });

    test('RFC 8032 test 2, one octet', () {
      final message = Uint8List.fromList(const [0x03]);
      _expectVector(
        secret:
            'c4eab05d357007c632f3dbb48489924d'
            '552b08fe0c353a0d4a1f00acda2c463a'
            'fbea67c5e8d2877c5e3bc397a659949e'
            'f8021e954e0a12274e',
        publicKey:
            '43ba28f430cdff456ae531545f7ecd0a'
            'c834a55d9358c0372bfa0c6c6798c086'
            '6aea01eb00742802b8438ea4cb82169c'
            '235160627b4c3a9480',
        message: message,
        signature:
            '26b8f91727bd62897af15e41eb43c377'
            'efb9c610d48f2335cb0bd0087810f435'
            '2541b143c4b981b7e18f62de8ccdf633'
            'fc1bf037ab7cd779805e0dbcc0aae1cb'
            'cee1afb2e027df36bc04dcecbf154336'
            'c19f0af7e0a6472905e799f1953d2a0f'
            'f3348ab21aa4adafd1d234441cf807c0'
            '3a00',
      );
    });

    test('RFC 8032 test 3, context foo', () {
      final message = Uint8List.fromList(const [0x03]);
      final context = Uint8List.fromList('foo'.codeUnits);
      _expectVector(
        secret:
            'c4eab05d357007c632f3dbb48489924d'
            '552b08fe0c353a0d4a1f00acda2c463a'
            'fbea67c5e8d2877c5e3bc397a659949e'
            'f8021e954e0a12274e',
        publicKey:
            '43ba28f430cdff456ae531545f7ecd0a'
            'c834a55d9358c0372bfa0c6c6798c086'
            '6aea01eb00742802b8438ea4cb82169c'
            '235160627b4c3a9480',
        message: message,
        signature:
            'd4f8f6131770dd46f40867d6fd5d5055'
            'de43541f8c5e35abbcd001b32a89f7d2'
            '151f7647f11d8ca2ae279fb842d60721'
            '7fce6e042f6815ea000c85741de5c8da'
            '1144a6a1aba7f96de42505d7a7298524'
            'fda538fccbbb754f578c1cad10d54d0d'
            '5428407e85dcbc98a49155c13764e66c'
            '3c00',
        context: context,
      );
    });

    test('a flipped message, a bad length, and S = L fail closed', () {
      final secret = Uint8List(57)..[0] = 4;
      final publicKey = PqEd448.publicKeyFromSeed(secret);
      final message = Uint8List.fromList('ed448'.codeUnits);
      final signature = PqEd448.sign(secretKey: secret, message: message);
      expect(signature.length, PqEd448.signatureBytes);
      expect(
        PqEd448.verify(
          publicKey: publicKey,
          message: message,
          signature: signature,
        ),
        isTrue,
      );
      final flipped = Uint8List.fromList(message)..[0] ^= 1;
      expect(
        PqEd448.verify(
          publicKey: publicKey,
          message: flipped,
          signature: signature,
        ),
        isFalse,
      );
      expect(
        PqEd448.verify(
          publicKey: Uint8List(56),
          message: message,
          signature: signature,
        ),
        isFalse,
      );
      final tooBig = Uint8List.fromList(signature);
      tooBig.setRange(57, 114, _orderLe());
      expect(
        PqEd448.verify(
          publicKey: publicKey,
          message: message,
          signature: tooBig,
        ),
        isFalse,
      );
      final nonCanonical = Uint8List.fromList(publicKey)..[56] = 0x01;
      expect(
        PqEd448.verify(
          publicKey: nonCanonical,
          message: message,
          signature: signature,
        ),
        isFalse,
      );
    });

    test('context and Ed448ph round-trip, and a foreign context does not', () {
      final secret = Uint8List.fromList(List<int>.generate(57, (i) => i));
      final publicKey = PqEd448.publicKeyFromSeed(secret);
      final message = Uint8List.fromList('context'.codeUnits);
      final context = Uint8List.fromList('dnssec'.codeUnits);
      final signature = PqEd448.sign(
        secretKey: secret,
        message: message,
        context: context,
      );
      expect(
        PqEd448.verify(
          publicKey: publicKey,
          message: message,
          signature: signature,
          context: context,
        ),
        isTrue,
      );
      expect(
        PqEd448.verify(
          publicKey: publicKey,
          message: message,
          signature: signature,
        ),
        isFalse,
      );
      final ph = PqEd448.sign(
        secretKey: secret,
        message: message,
        preHash: true,
      );
      expect(
        PqEd448.verify(
          publicKey: publicKey,
          message: message,
          signature: ph,
          preHash: true,
        ),
        isTrue,
      );
      expect(
        PqEd448.verify(publicKey: publicKey, message: message, signature: ph),
        isFalse,
      );
    });

    test('matches OpenSSL on a fresh Ed448 key', () {
      final dir = Directory.systemTemp.createTempSync('ed448');
      final pem = '${dir.path}/key.pem';
      final generated = Process.runSync('openssl', [
        'genpkey',
        '-algorithm',
        'ED448',
        '-out',
        pem,
      ]);
      expect(generated.exitCode, 0, reason: '${generated.stderr}');
      final text = Process.runSync('openssl', [
        'pkey',
        '-in',
        pem,
        '-text',
        '-noout',
      ]);
      expect(text.exitCode, 0, reason: '${text.stderr}');
      final fields = _opensslFields(text.stdout as String);
      final secret = fields['priv']!;
      final publicKey = fields['pub']!;
      expect(secret, hasLength(57));
      expect(publicKey, hasLength(57));
      expect(PqEd448.publicKeyFromSeed(secret), orderedEquals(publicKey));
      final message = Uint8List.fromList('openssl ed448'.codeUnits);
      final signature = PqEd448.sign(secretKey: secret, message: message);
      final msg = File('${dir.path}/msg')..writeAsBytesSync(message);
      final sig = File('${dir.path}/sig')..writeAsBytesSync(signature);
      final verified = Process.runSync('openssl', [
        'pkeyutl',
        '-verify',
        '-inkey',
        pem,
        '-rawin',
        '-in',
        msg.path,
        '-sigfile',
        sig.path,
      ]);
      expect(verified.exitCode, 0, reason: '${verified.stderr}');
      final opensslSig = File('${dir.path}/ossl.sig');
      final signed = Process.runSync('openssl', [
        'pkeyutl',
        '-sign',
        '-inkey',
        pem,
        '-rawin',
        '-in',
        msg.path,
        '-out',
        opensslSig.path,
      ]);
      expect(signed.exitCode, 0, reason: '${signed.stderr}');
      expect(opensslSig.readAsBytesSync(), orderedEquals(signature));
    });
  });
}

void _expectVector({
  required String secret,
  required String publicKey,
  required Uint8List message,
  required String signature,
  Uint8List? context,
}) {
  final seed = _hex(secret);
  final pub = _hex(publicKey);
  final sig = _hex(signature);
  expect(seed.length, 57);
  expect(pub.length, 57);
  expect(sig.length, 114);
  expect(PqEd448.publicKeyFromSeed(seed), orderedEquals(pub));
  expect(
    PqEd448.sign(secretKey: seed, message: message, context: context),
    orderedEquals(sig),
  );
  expect(
    PqEd448.verify(
      publicKey: pub,
      message: message,
      signature: sig,
      context: context,
    ),
    isTrue,
  );
}

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Little-endian 57-byte encoding of L. Bit 446 and above are clear in a
/// reduced scalar, so this value must be rejected.
Uint8List _orderLe() {
  final hex =
      '3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3';
  final be = _hex(hex);
  final out = Uint8List(57);
  for (var i = 0; i < be.length; i++) {
    out[i] = be[be.length - 1 - i];
  }
  return out;
}

Map<String, Uint8List> _opensslFields(String text) {
  final out = <String, Uint8List>{};
  String? name;
  final hex = StringBuffer();
  for (final raw in text.split('\n')) {
    final line = raw.trim();
    if (line.endsWith(':') && RegExp('[g-z]').hasMatch(line)) {
      if (name != null) out[name] = _hex(hex.toString());
      name = line.substring(0, line.length - 1);
      hex.clear();
      continue;
    }
    if (RegExp(r'^[0-9a-f:]+$').hasMatch(line)) {
      hex.write(line.replaceAll(':', ''));
    }
  }
  if (name != null && hex.isNotEmpty) out[name] = _hex(hex.toString());
  return out;
}
