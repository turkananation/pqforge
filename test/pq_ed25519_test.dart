import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqEd25519', () {
    test('RFC 8032 test 1, empty message', () {
      final secret = _hex(
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      );
      final publicKey = _hex(
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
      );
      final signature = _hex(
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
        '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
      );
      expect(PqEd25519.publicKeyFromSeed(secret), orderedEquals(publicKey));
      expect(
        PqEd25519.sign(secretKey: secret, message: Uint8List(0)),
        orderedEquals(signature),
      );
      expect(
        PqEd25519.verify(
          publicKey: publicKey,
          message: Uint8List(0),
          signature: signature,
        ),
        isTrue,
      );
    });

    test('RFC 8032 test 2, message r', () {
      final secret = _hex(
        '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
      );
      final publicKey = _hex(
        '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
      );
      final message = Uint8List.fromList(<int>[0x72]);
      final signature = _hex(
        '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
        '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
      );
      expect(PqEd25519.publicKeyFromSeed(secret), orderedEquals(publicKey));
      expect(
        PqEd25519.sign(secretKey: secret, message: message),
        orderedEquals(signature),
      );
      expect(
        PqEd25519.verify(
          publicKey: publicKey,
          message: message,
          signature: signature,
        ),
        isTrue,
      );
    });

    test('matches the async provider and rejects a flipped bit', () async {
      final secret = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
      final publicKey = PqEd25519.publicKeyFromSeed(secret);
      final message = Uint8List.fromList('ed25519 sync'.codeUnits);
      final signature = PqEd25519.sign(secretKey: secret, message: message);
      final asyncOk = await crypto.Ed25519().verify(
        message,
        signature: crypto.Signature(
          signature,
          publicKey: crypto.SimplePublicKey(
            publicKey,
            type: crypto.KeyPairType.ed25519,
          ),
        ),
      );
      expect(asyncOk, isTrue);
      final flipped = Uint8List.fromList(message)..[0] ^= 1;
      expect(
        PqEd25519.verify(
          publicKey: publicKey,
          message: flipped,
          signature: signature,
        ),
        isFalse,
      );
    });

    test('verify returns false for a short key', () {
      expect(
        PqEd25519.verify(
          publicKey: Uint8List(31),
          message: Uint8List(0),
          signature: Uint8List(64),
        ),
        isFalse,
      );
    });
  });
}

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
