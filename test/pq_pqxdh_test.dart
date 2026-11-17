import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart' as pqc;
import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  tearDown(PqFipsMode.disable);

  group('PQXDH revision 3', () {
    test('SK matches an independent HKDF of the spec concatenation', () async {
      final coins = _fill(32, 3);
      final parties = await _fixed(coins: coins, oneTime: false);
      final alice = parties.alice;
      final bob = parties.bob;
      final opened = parties.opened;
      expect(opened.sharedSecret.bytes, alice.sharedSecret.bytes);
      expect(opened.plaintext, _text('hello'));
      expect(opened.initialMessage, isNull);

      final dh1 = await PqForgeHybridKeyAgreement.x25519SharedSecret(
        secretKey: parties.aliceKey.secretKey,
        remotePublicKey: bob.signedPrekey.publicKey.bytes,
      );
      final dh2 = await PqForgeHybridKeyAgreement.x25519SharedSecret(
        secretKey: parties.ephemeral.secretKey,
        remotePublicKey: bob.identityKey.publicKey.bytes,
      );
      final dh3 = await PqForgeHybridKeyAgreement.x25519SharedSecret(
        secretKey: parties.ephemeral.secretKey,
        remotePublicKey: bob.signedPrekey.publicKey.bytes,
      );
      final encapsulated = PqLattice.provider.kemEncapsulate(
        PqKemAlgorithm.mlKem1024,
        bob.bundle.kemPublicKey,
        nonce: coins,
      );
      final expected = _hkdf32(
        _ikm([dh1, dh2, dh3, encapsulated.$2]),
        utf8.encode('pqforge01_${Pqxdh.hkdfParameters}'),
      );
      expect(alice.sharedSecret.bytes, expected);
      expect(bob.bundle.kemPublicKey, isNot(encapsulated.$1));
    });

    test('a one-time prekey changes SK and is required to open', () async {
      final coins = _fill(32, 5);
      final withOneTime = await _fixed(coins: coins, oneTime: true);
      final without = await _fixed(coins: coins, oneTime: false);
      expect(
        withOneTime.alice.sharedSecret.bytes,
        isNot(without.alice.sharedSecret.bytes),
      );
      final message = withOneTime.alice.initialMessage!;
      expect(message.usedOneTimePrekey, isTrue);
      await expectLater(
        Pqxdh.accept(
          identityKey: withOneTime.bob.identityKey,
          signedPrekey: withOneTime.bob.signedPrekey,
          kemSecretKey: withOneTime.bob.kemSecretKey,
          initialMessage: message,
        ),
        throwsA(isA<PqForgeException>()),
      );
    });

    test('different KEM coins do not reproduce SK', () async {
      final first = await _fixed(coins: _fill(32, 1), oneTime: false);
      final second = await _fixed(coins: _fill(32, 2), oneTime: false);
      expect(
        first.alice.sharedSecret.bytes,
        isNot(second.alice.sharedSecret.bytes),
      );
    });

    test('a bad signed-prekey signature derives nothing', () async {
      final parties = await _fixed(coins: _fill(32, 4), oneTime: false);
      final bundle = parties.bob.bundle;
      final bad = Uint8List.fromList(bundle.signedPrekeySignature)..[0] ^= 1;
      final forged = PqxdhBundle(
        identityKey: bundle.identityKey,
        signedPrekey: bundle.signedPrekey,
        signedPrekeySignature: bad,
        kemPublicKeySignature: bundle.kemPublicKeySignature,
        kemPublicKey: bundle.kemPublicKey,
      );
      await expectLater(
        Pqxdh.initiate(identityKey: parties.aliceKey, bundle: forged),
        throwsA(
          isA<PqForgeException>().having(
            (error) => error.message,
            'message',
            contains('No secret was derived'),
          ),
        ),
      );
    });

    test('a bad KEM-prekey signature derives nothing', () async {
      final parties = await _fixed(coins: _fill(32, 6), oneTime: false);
      final bundle = parties.bob.bundle;
      final bad = Uint8List.fromList(bundle.kemPublicKeySignature)..[2] ^= 4;
      final forged = PqxdhBundle(
        identityKey: bundle.identityKey,
        signedPrekey: bundle.signedPrekey,
        signedPrekeySignature: bundle.signedPrekeySignature,
        kemPublicKeySignature: bad,
        kemPublicKey: bundle.kemPublicKey,
      );
      expect(Pqxdh.kemPrekeyAuthentic(forged), isFalse);
      await expectLater(
        Pqxdh.initiate(identityKey: parties.aliceKey, bundle: forged),
        throwsA(isA<PqForgeException>()),
      );
    });

    test(
      'dropping the KEM public key from the associated data fails',
      () async {
        final parties = await _fixed(coins: _fill(32, 8), oneTime: false);
        final message = parties.alice.initialMessage!;
        final full = Pqxdh.associatedData(
          aliceIdentity: parties.aliceKey.publicKey.bytes,
          bobIdentity: parties.bob.identityKey.publicKey.bytes,
          kemPublicKey: parties.bob.bundle.kemPublicKey,
        );
        expect(full.length, 64 + 1568);
        expect(
          () => PqSymmetricPrimitives.aesGcmDecrypt(
            key: parties.alice.sharedSecret.bytes,
            nonce: Uint8List(12),
            ciphertext: message.sealed,
            aad: Uint8List.sublistView(full, 0, 64),
          ),
          throwsA(isA<PqForgeAuthTagException>()),
        );
        final flipped = Uint8List.fromList(message.bytes);
        flipped[flipped.length - 1] ^= 1;
        await expectLater(
          Pqxdh.accept(
            identityKey: parties.bob.identityKey,
            signedPrekey: parties.bob.signedPrekey,
            kemSecretKey: parties.bob.kemSecretKey,
            initialMessage: PqxdhMessage.parse(flipped),
          ),
          throwsA(isA<PqForgeAuthTagException>()),
        );
      },
    );

    test('the next ratchet message opens, and the initial one is not a ratchet message', () async {
      final parties = await _fixed(coins: _fill(32, 9), oneTime: false);
      final sealed = parties.alice.ratchet.seal(_text('second'));
      expect(await parties.opened.ratchet.open(sealed), _text('second'));
      await expectLater(
        parties.opened.ratchet.open(
          DoubleRatchetMessage.parse(parties.alice.initialMessage!.bytes),
        ),
        throwsA(anyOf(isA<PqForgeException>(), isA<PqForgeAuthTagException>())),
      );
    });

    test(
      'an all-zero signed prekey is rejected before SK is returned',
      () async {
        final bob = await Pqxdh.publish(
          identitySeed: _fill(32, 11),
          signedPrekeySeed: _fill(32, 12),
          kemSeed: _fill(64, 13),
          signatureRandomness: _fill(64, 14),
        );
        final zero = RatchetPublicKey(Uint8List(32));
        final signature = PqXeddsa.sign(
          secretKey: bob.identityKey.secretKey,
          message: zero.bytes,
          randomness: _fill(64, 15),
        );
        final bundle = PqxdhBundle(
          identityKey: bob.bundle.identityKey,
          signedPrekey: zero,
          signedPrekeySignature: signature,
          kemPublicKeySignature: bob.bundle.kemPublicKeySignature,
          kemPublicKey: bob.bundle.kemPublicKey,
        );
        final alice = await RatchetKeyPair.generate(seed: _fill(32, 16));
        await expectLater(
          Pqxdh.initiate(
            identityKey: alice,
            bundle: bundle,
            kemCoins: _fill(32, 17),
            ephemeralSeed: _fill(32, 18),
          ),
          throwsA(
            isA<PqForgeException>().having(
              (error) => error.message,
              'message',
              contains('all zeros'),
            ),
          ),
        );
      },
    );

    test('info shorter than 8 characters is rejected', () async {
      final parties = await _fixed(coins: _fill(32, 19), oneTime: false);
      expect(
        () => Pqxdh.initiate(
          identityKey: parties.aliceKey,
          bundle: parties.bob.bundle,
          info: 'short',
        ),
        throwsArgumentError,
      );
    });

    test('ChaCha opens, and FIPS mode refuses it', () async {
      final bob = await Pqxdh.publish(kemSeed: _fill(64, 21));
      final aliceKey = await RatchetKeyPair.generate();
      final alice = await Pqxdh.initiate(
        identityKey: aliceKey,
        bundle: bob.bundle,
        plaintext: _text('chacha'),
        suite: PqForgeCipherSuite.chaCha20Poly1305,
      );
      final opened = await Pqxdh.accept(
        identityKey: bob.identityKey,
        signedPrekey: bob.signedPrekey,
        kemSecretKey: bob.kemSecretKey,
        initialMessage: alice.initialMessage!,
        suite: PqForgeCipherSuite.chaCha20Poly1305,
      );
      expect(opened.plaintext, _text('chacha'));
      PqFipsMode.enable();
      await expectLater(
        Pqxdh.initiate(
          identityKey: aliceKey,
          bundle: bob.bundle,
          suite: PqForgeCipherSuite.chaCha20Poly1305,
        ),
        throwsA(isA<PqForgeException>()),
      );
    });

    test('empty and long plaintexts round-trip under AES-GCM', () async {
      final bob = await Pqxdh.publish();
      final aliceKey = await RatchetKeyPair.generate();
      for (final plain in [Uint8List(0), _fill(4096, 23)]) {
        final alice = await Pqxdh.initiate(
          identityKey: aliceKey,
          bundle: bob.bundle,
          plaintext: plain,
        );
        final opened = await Pqxdh.accept(
          identityKey: bob.identityKey,
          signedPrekey: bob.signedPrekey,
          kemSecretKey: bob.kemSecretKey,
          initialMessage: alice.initialMessage!,
        );
        expect(opened.plaintext, plain);
      }
    });

    test(
      'the decapsulation key embeds the published encapsulation key',
      () async {
        final bob = await Pqxdh.publish(kemSeed: _fill(64, 24));
        final embedded = Uint8List.sublistView(
          bob.kemSecretKey,
          1536,
          1536 + PqxdhKem.kyber1024.publicKeyBytes,
        );
        expect(embedded, bob.bundle.kemPublicKey);
        bob.wipe();
        expect(bob.kemSecretKey, everyElement(0));
      },
    );

    test('a truncated message and an unknown version are rejected', () {
      expect(
        () => PqxdhMessage.parse(Uint8List(80)),
        throwsA(isA<PqForgeException>()),
      );
      final bytes = Uint8List(70 + 1568 + 16);
      bytes[0] = 0x50;
      bytes[1] = 0x51;
      bytes[2] = 0x58;
      bytes[3] = 0x31;
      bytes[4] = 9;
      expect(() => PqxdhMessage.parse(bytes), throwsA(isA<PqForgeException>()));
    });
  });
}

final class _Parties {
  _Parties(this.aliceKey, this.ephemeral, this.bob, this.alice, this.opened);

  final RatchetKeyPair aliceKey;
  final RatchetKeyPair ephemeral;
  final PqxdhPrekeys bob;
  final PqxdhResult alice;
  final PqxdhResult opened;
}

Future<_Parties> _fixed({
  required Uint8List coins,
  required bool oneTime,
}) async {
  final bob = await Pqxdh.publish(
    identitySeed: _fill(32, 30),
    signedPrekeySeed: _fill(32, 31),
    oneTimePrekey: oneTime,
    oneTimePrekeySeed: _fill(32, 32),
    kemSeed: _fill(64, 33),
    signatureRandomness: _fill(64, 34),
  );
  final aliceKey = await RatchetKeyPair.generate(seed: _fill(32, 35));
  final ephemeral = await RatchetKeyPair.generate(seed: _fill(32, 36));
  final alice = await Pqxdh.initiate(
    identityKey: aliceKey,
    bundle: bob.bundle,
    plaintext: _text('hello'),
    ephemeralSeed: _fill(32, 36),
    kemCoins: coins,
  );
  final opened = await Pqxdh.accept(
    identityKey: bob.identityKey,
    signedPrekey: bob.signedPrekey,
    kemSecretKey: bob.kemSecretKey,
    oneTimePrekey: bob.oneTimePrekey,
    initialMessage: alice.initialMessage!,
  );
  return _Parties(aliceKey, ephemeral, bob, alice, opened);
}

Uint8List _fill(int length, int value) =>
    Uint8List(length)..fillRange(0, length, value);

Uint8List _text(String value) => Uint8List.fromList(utf8.encode(value));

Uint8List _ikm(List<Uint8List> parts) {
  var length = 32;
  for (final part in parts) {
    length += part.length;
  }
  final out = Uint8List(length);
  out.fillRange(0, 32, 0xff);
  var offset = 32;
  for (final part in parts) {
    out.setRange(offset, offset + part.length, part);
    offset += part.length;
  }
  return out;
}

/// Independent HKDF-SHA-512. Not [Pqxdh]'s private function.
Uint8List _hkdf32(Uint8List ikm, List<int> infoBytes) {
  final info = Uint8List.fromList(infoBytes);
  final prk = pqc.hmacSha512(Uint8List(64), ikm);
  final data = Uint8List(info.length + 1)..setRange(0, info.length, info);
  data[info.length] = 1;
  final block = pqc.hmacSha512(prk, data);
  return Uint8List.sublistView(block, 0, 32);
}
