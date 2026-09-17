import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqNistEcdh P-256', () {
    test('two parties agree on a 32-byte x-coordinate', () async {
      final a = PqNistEcdh.p256GenerateKeyPair();
      final b = PqNistEcdh.p256GenerateKeyPair();
      expect(a.publicKey, hasLength(65));
      expect(a.publicKey.first, 0x04);
      expect(a.secretKey, hasLength(32));
      final ab = PqNistEcdh.p256SharedSecret(
        secretKey: a.secretKey,
        remotePublicKey: b.publicKey,
      );
      final ba = PqNistEcdh.p256SharedSecret(
        secretKey: b.secretKey,
        remotePublicKey: a.publicKey,
      );
      expect(ab, orderedEquals(ba));
      expect(ab, hasLength(32));
      expect(ab.any((byte) => byte != 0), isTrue);
    });

    test('matches RFC 5903 §8.1 public keys and shared secret', () {
      final dA = _hex(
        'C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433',
      );
      final dB = _hex(
        'C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53',
      );
      final qA = _hex(
        '04'
        'DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180'
        '5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3',
      );
      final qB = _hex(
        '04'
        'D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63'
        '56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB',
      );
      final z = _hex(
        'D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE',
      );
      expect(PqNistEcdh.p256PublicKeyFromPrivate(dA), orderedEquals(qA));
      expect(PqNistEcdh.p256PublicKeyFromPrivate(dB), orderedEquals(qB));
      final seeded = PqNistEcdh.p256GenerateKeyPair(seed: dA);
      expect(seeded.publicKey, orderedEquals(qA));
      expect(seeded.secretKey, orderedEquals(dA));
      expect(
        PqNistEcdh.p256SharedSecret(secretKey: dA, remotePublicKey: qB),
        orderedEquals(z),
      );
      expect(
        PqNistEcdh.p256SharedSecret(secretKey: dB, remotePublicKey: qA),
        orderedEquals(z),
      );
    });

    test('hybrid helper routes through the classical seam', () async {
      final a = await PqForgeHybridKeyAgreement.generateP256KeyPairBytes();
      final b = await PqForgeHybridKeyAgreement.generateP256KeyPairBytes();
      final ss = await PqForgeHybridKeyAgreement.p256SharedSecret(
        secretKey: a.secretKey,
        remotePublicKey: b.publicKey,
      );
      expect(ss, hasLength(32));
    });

    test('rejects wrong length, missing 0x04, and truncated points', () {
      final a = PqNistEcdh.p256GenerateKeyPair();
      final b = PqNistEcdh.p256GenerateKeyPair();
      expect(
        () => PqNistEcdh.p256SharedSecret(
          secretKey: Uint8List(31),
          remotePublicKey: b.publicKey,
        ),
        throwsArgumentError,
      );
      expect(
        () => PqNistEcdh.p256SharedSecret(
          secretKey: a.secretKey,
          remotePublicKey: Uint8List.sublistView(b.publicKey, 0, 64),
        ),
        throwsArgumentError,
      );
      final compressed = Uint8List.fromList(b.publicKey)..[0] = 0x02;
      expect(
        () => PqNistEcdh.p256SharedSecret(
          secretKey: a.secretKey,
          remotePublicKey: compressed,
        ),
        throwsArgumentError,
      );
    });

    test('rejects off-curve points, (0,0), and out-of-range scalars', () {
      final a = PqNistEcdh.p256GenerateKeyPair();
      final b = PqNistEcdh.p256GenerateKeyPair();
      final offCurve = Uint8List.fromList(b.publicKey);
      offCurve[offCurve.length - 1] ^= 0x01;
      expect(
        () => PqNistEcdh.p256SharedSecret(
          secretKey: a.secretKey,
          remotePublicKey: offCurve,
        ),
        throwsArgumentError,
      );
      final origin = Uint8List(65)..[0] = 0x04;
      expect(
        () => PqNistEcdh.p256SharedSecret(
          secretKey: a.secretKey,
          remotePublicKey: origin,
        ),
        throwsArgumentError,
      );
      expect(
        () => PqNistEcdh.p256PublicKeyFromPrivate(Uint8List(32)),
        throwsArgumentError,
      );
      expect(
        () => PqNistEcdh.p256GenerateKeyPair(
          seed: Uint8List(32)..fillRange(0, 32, 0xff),
        ),
        throwsArgumentError,
      );
    });

    test('P-256 ECDH keys are interchangeable with PqEcdsaP256', () {
      final sig = PqEcdsaP256.generateKeyPair();
      final peer = PqNistEcdh.p256GenerateKeyPair();
      final ss = PqNistEcdh.p256SharedSecret(
        secretKey: sig.secretKey,
        remotePublicKey: peer.publicKey,
      );
      expect(ss, hasLength(32));
      expect(
        PqNistEcdh.p256PublicKeyFromPrivate(sig.secretKey),
        orderedEquals(sig.publicKey),
      );
    });
  });

  group('PqNistEcdh P-384', () {
    test('two parties agree on a 48-byte x-coordinate', () {
      final a = PqNistEcdh.p384GenerateKeyPair();
      final b = PqNistEcdh.p384GenerateKeyPair();
      expect(a.publicKey, hasLength(97));
      expect(a.publicKey.first, 0x04);
      expect(a.secretKey, hasLength(48));
      final ab = PqNistEcdh.p384SharedSecret(
        secretKey: a.secretKey,
        remotePublicKey: b.publicKey,
      );
      final ba = PqNistEcdh.p384SharedSecret(
        secretKey: b.secretKey,
        remotePublicKey: a.publicKey,
      );
      expect(ab, orderedEquals(ba));
      expect(ab, hasLength(48));
    });

    test('matches RFC 5903 §8.2 public keys and shared secret', () {
      final dA = _hex(
        '099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655'
        'E35B538041E649EE3FAEF896783AB194',
      );
      final dB = _hex(
        '41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942'
        'E0308312916B8ED2960E4BD55A7448FC',
      );
      final qA = _hex(
        '04'
        '667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6'
        'DE3AC808ACB4BDB4C88732AEE95F41AA'
        '9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38E'
        'EB9FCFF3C2C947DAE69B4C634573A81C',
      );
      final qB = _hex(
        '04'
        'E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D'
        '0D1AC43A0336DEF96FDA41D0774A3571'
        'DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FF'
        'F83FA40142209DFF5EAAD96DB9E6386C',
      );
      final z = _hex(
        '11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4'
        'D603135569B9E9D09CF5D4A270F59746',
      );
      expect(PqNistEcdh.p384PublicKeyFromPrivate(dA), orderedEquals(qA));
      expect(PqNistEcdh.p384PublicKeyFromPrivate(dB), orderedEquals(qB));
      expect(
        PqNistEcdh.p384SharedSecret(secretKey: dA, remotePublicKey: qB),
        orderedEquals(z),
      );
      expect(
        PqNistEcdh.p384SharedSecret(secretKey: dB, remotePublicKey: qA),
        orderedEquals(z),
      );
    });

    test('hybrid helper routes through the classical seam', () async {
      final a = await PqForgeHybridKeyAgreement.generateP384KeyPairBytes();
      final b = await PqForgeHybridKeyAgreement.generateP384KeyPairBytes();
      final ss = await PqForgeHybridKeyAgreement.p384SharedSecret(
        secretKey: a.secretKey,
        remotePublicKey: b.publicKey,
      );
      expect(ss, hasLength(48));
    });

    test('rejects missing 0x04 prefix and off-curve points', () {
      final a = PqNistEcdh.p384GenerateKeyPair();
      final b = PqNistEcdh.p384GenerateKeyPair();
      final bad = Uint8List.fromList(b.publicKey)..[0] = 0x03;
      expect(
        () => PqNistEcdh.p384SharedSecret(
          secretKey: a.secretKey,
          remotePublicKey: bad,
        ),
        throwsArgumentError,
      );
      final offCurve = Uint8List.fromList(b.publicKey);
      offCurve[40] ^= 0x01;
      expect(
        () => PqNistEcdh.p384SharedSecret(
          secretKey: a.secretKey,
          remotePublicKey: offCurve,
        ),
        throwsArgumentError,
      );
    });
  });
}

Uint8List _hex(String hex) {
  final compact = hex.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList([
    for (var i = 0; i < compact.length; i += 2)
      int.parse(compact.substring(i, i + 2), radix: 16),
  ]);
}
