import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  test('RFC 7748 X448 ladder vector', () {
    final shared = PqX448.sharedSecret(
      secretKey: _hex(
        '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121'
        '700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3',
      ),
      remotePublicKey: _hex(
        '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9'
        '814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086',
      ),
    );
    expect(
      shared,
      _hex(
        'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f'
        'e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f',
      ),
    );
  });

  test('RFC 7748 X448 Diffie-Hellman vector', () {
    final alice = _hex(
      '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d'
      'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b',
    );
    final bob = _hex(
      '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d'
      '6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d',
    );
    final alicePublic = PqX448.publicKeyFromPrivate(alice);
    final bobPublic = PqX448.publicKeyFromPrivate(bob);
    expect(
      alicePublic,
      _hex(
        '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c'
        '22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0',
      ),
    );
    expect(
      bobPublic,
      _hex(
        '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430'
        '27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609',
      ),
    );
    final secret = _hex(
      '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b'
      'b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d',
    );
    expect(
      PqX448.sharedSecret(secretKey: alice, remotePublicKey: bobPublic),
      secret,
    );
    expect(
      PqX448.sharedSecret(secretKey: bob, remotePublicKey: alicePublic),
      secret,
    );
  });

  test('a fresh X448 pair agrees, and the base point is u = 5', () {
    expect(PqX448.basePoint[0], 5);
    expect(PqX448.basePoint.sublist(1), Uint8List(55));
    final alice = PqX448.generateKeyPair();
    final bob = PqX448.generateKeyPair();
    expect(
      PqX448.sharedSecret(
        secretKey: alice.secretKey,
        remotePublicKey: bob.publicKey,
      ),
      PqX448.sharedSecret(
        secretKey: bob.secretKey,
        remotePublicKey: alice.publicKey,
      ),
    );
    expect(alice.publicKey, isNot(alice.secretKey));
  });
}

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
