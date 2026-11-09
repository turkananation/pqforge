import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

import 'xwing_vectors.dart';

void main() {
  final records =
      <
        ({
          Uint8List seed,
          Uint8List sk,
          Uint8List pk,
          Uint8List eseed,
          Uint8List ct,
          Uint8List ss,
        })
      >[
        (
          seed: xwingSeed1,
          sk: xwingSk1,
          pk: xwingPk1,
          eseed: xwingEseed1,
          ct: xwingCt1,
          ss: xwingSs1,
        ),
        (
          seed: xwingSeed2,
          sk: xwingSk2,
          pk: xwingPk2,
          eseed: xwingEseed2,
          ct: xwingCt2,
          ss: xwingSs2,
        ),
        (
          seed: xwingSeed3,
          sk: xwingSk3,
          pk: xwingPk3,
          eseed: xwingEseed3,
          ct: xwingCt3,
          ss: xwingSs3,
        ),
      ];

  test('draft-11 Appendix C lengths', () {
    for (final record in records) {
      expect(record.seed, record.sk);
      expect(record.seed, hasLength(32));
      expect(record.pk, hasLength(1216));
      expect(record.eseed, hasLength(64));
      expect(record.ct, hasLength(1120));
      expect(record.ss, hasLength(32));
    }
  });

  test('draft-connolly-cfrg-xwing-kem-11 Appendix C', () async {
    for (final record in records) {
      final pair = await PqXWing.generateKeyPairDerand(record.seed);
      expect(pair.publicKey, record.pk);
      expect(pair.secretKey, record.seed);

      final enc = await PqXWing.encapsulateDerand(record.pk, record.eseed);
      expect(enc.ciphertext, record.ct);
      expect(enc.sharedSecret, record.ss);

      final opened = await PqXWing.decapsulate(record.ct, record.seed);
      expect(opened, record.ss);
    }
  });

  test('lengths are exact', () async {
    final pair = await PqXWing.generateKeyPairDerand(xwingSeed1);
    expect(
      () => PqXWing.generateKeyPairDerand(Uint8List(64)),
      throwsArgumentError,
    );
    expect(
      () => PqXWing.generateKeyPairDerand(Uint8List(31)),
      throwsArgumentError,
    );
    expect(
      () => PqXWing.encapsulateDerand(pair.publicKey, Uint8List(32)),
      throwsArgumentError,
    );
    expect(
      () => PqXWing.encapsulateDerand(Uint8List(1215), xwingEseed1),
      throwsArgumentError,
    );
    expect(
      () => PqXWing.decapsulate(Uint8List(1119), xwingSeed1),
      throwsArgumentError,
    );
    expect(
      () => PqXWing.decapsulate(Uint8List(1121), xwingSeed1),
      throwsArgumentError,
    );
  });

  test('a flipped ciphertext still returns 32 bytes', () async {
    final flippedM = Uint8List.fromList(xwingCt1)..[0] ^= 0x01;
    final fromM = await PqXWing.decapsulate(flippedM, xwingSeed1);
    expect(fromM, hasLength(32));
    expect(fromM, isNot(xwingSs1));

    final flippedX = Uint8List.fromList(xwingCt1)..[1119] ^= 0x01;
    final fromX = await PqXWing.decapsulate(flippedX, xwingSeed1);
    expect(fromX, hasLength(32));
    expect(fromX, isNot(xwingSs1));
  });

  test('an all-zero X25519 public key still encapsulates', () async {
    final pk = Uint8List.fromList(xwingPk1)..fillRange(1184, 1216, 0);
    final enc = await PqXWing.encapsulateDerand(pk, xwingEseed1);
    expect(enc.sharedSecret, hasLength(32));
    expect(enc.ciphertext, hasLength(1120));
  });

  test(
    'a broken ML-KEM public key fails before a ciphertext is returned',
    () async {
      final pk = Uint8List.fromList(xwingPk1);
      // 12-bit coefficient 0x0D01 = 3329 = q. FIPS 203 §7.2 rejects it.
      pk[0] = 0x01;
      pk[1] = 0x0d;
      expect(
        () => PqXWing.encapsulateDerand(pk, xwingEseed1),
        throwsA(isA<PqForgeException>()),
      );
    },
  );

  test('the returned secret is a copy', () async {
    final first = await PqXWing.decapsulate(xwingCt1, xwingSeed1);
    first[0] ^= 0xff;
    final second = await PqXWing.decapsulate(xwingCt1, xwingSeed1);
    expect(second, xwingSs1);
  });

  test('two generated public keys differ', () async {
    final a = await PqXWing.generateKeyPair();
    final b = await PqXWing.generateKeyPair();
    expect(a.publicKey, isNot(b.publicKey));
    expect(a.secretKey, hasLength(32));
  });

  test('DeriveKeyPair hashes a 32-byte ikm', () async {
    final ikm = Uint8List.fromList(xwingSeed1);
    final derived = await PqXWing.generateKeyPairDerand(
      PqXWing.deriveSeed(ikm),
    );
    final raw = await PqXWing.generateKeyPairDerand(ikm);
    expect(derived.publicKey, isNot(raw.publicKey));
    final again = await PqXWing.generateKeyPairDerand(PqXWing.deriveSeed(ikm));
    expect(again.publicKey, derived.publicKey);
    final empty = PqXWing.deriveSeed(Uint8List(0));
    expect(empty, hasLength(32));
  });

  test('known answers still pass while FIPS mode is on', () async {
    PqFipsMode.enable();
    try {
      final pair = await PqXWing.generateKeyPairDerand(xwingSeed1);
      expect(pair.publicKey, xwingPk1);
    } finally {
      PqFipsMode.disable();
    }
  });
}
