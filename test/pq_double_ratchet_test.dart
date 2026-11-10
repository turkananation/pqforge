import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart' as pqc;
import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  tearDown(PqFipsMode.disable);

  group('Double Ratchet', () {
    test('exchanges messages, including one that arrives late', () async {
      final secret = SharedSecret32(_pattern(32, 7));
      final bobKey = await RatchetKeyPair.generate();
      final alice = await DoubleRatchet.initiate(
        sharedSecret: secret,
        remoteRatchetKey: bobKey.publicKey,
      );
      final bob = DoubleRatchet.accept(
        sharedSecret: secret,
        ratchetKey: bobKey,
      );
      bobKey.wipe();

      expect(
        () => bob.seal(_text('too soon')),
        throwsA(isA<PqForgeException>()),
      );

      final aad = _text('turn');
      final first = alice.seal(_text('one'), aad: aad);
      final second = alice.seal(_text('two'), aad: aad);
      final third = alice.seal(_text('three'), aad: aad);
      expect(first.header.length, DoubleRatchetMessage.headerBytes);
      expect(first.pn, 0);
      expect(first.n, 0);
      expect(second.n, 1);
      expect(third.n, 2);
      expect(first.bytes.length, 40 + _text('one').length + 16);

      expect(await bob.open(second, aad: aad), _text('two'));
      expect(bob.skippedCount, 1);
      expect(await bob.open(first, aad: aad), _text('one'));
      expect(bob.skippedCount, 0);
      expect(await bob.open(third, aad: aad), _text('three'));

      final reply = bob.seal(_text('reply'), aad: aad);
      expect(reply.pn, 0);
      expect(reply.n, 0);
      expect(await alice.open(reply, aad: aad), _text('reply'));
      expect(
        await bob.open(alice.seal(_text('again'), aad: aad), aad: aad),
        _text('again'),
      );

      alice.dispose();
      bob.dispose();
      expect(() => alice.seal(_text('gone')), throwsStateError);
      expect(() => bob.open(reply), throwsStateError);
      alice.dispose();
    });

    test('a header past maxSkip does not grow the skipped-key map', () async {
      final parties = await _pair(maxSkip: 1);
      final alice = parties.$1;
      final bob = parties.$2;
      final messages = [
        alice.seal(_text('0')),
        alice.seal(_text('1')),
        alice.seal(_text('2')),
      ];

      await expectLater(
        bob.open(messages[2]),
        throwsA(isA<PqForgeException>()),
      );
      expect(bob.skippedCount, 0);
      expect(await bob.open(messages[0]), _text('0'));
      expect(await bob.open(messages[1]), _text('1'));
      expect(bob.skippedCount, 0);
      alice.seal(_text('3'));
      final far = alice.seal(_text('4'));
      await expectLater(bob.open(far), throwsA(isA<PqForgeException>()));
      expect(bob.skippedCount, 0);
    });

    test(
      'a Diffie-Hellman step does not continue the old sending chain',
      () async {
        final parties = await _pair();
        final alice = parties.$1;
        final bob = parties.$2;
        expect(await bob.open(alice.seal(_text('hello'))), _text('hello'));
        final oldChain = alice.copySendingChainKey()!;
        expect(await alice.open(bob.seal(_text('hi'))), _text('hi'));
        final newChain = alice.copySendingChainKey()!;

        final continued = _hmac32(oldChain, 0x02, DoubleRatchetHash.sha256);
        final oldMessageKey = _hmac32(oldChain, 0x01, DoubleRatchetHash.sha256);
        final newMessageKey = _hmac32(newChain, 0x01, DoubleRatchetHash.sha256);
        expect(newChain, isNot(oldChain));
        expect(newChain, isNot(continued));
        expect(newMessageKey, isNot(oldMessageKey));
        expect(await bob.open(alice.seal(_text('after'))), _text('after'));
      },
    );

    test(
      'PqXWing.decapsulate seeds a session; a public key does not',
      () async {
        final kem = await PqXWing.generateKeyPair();
        final encapsulated = await PqXWing.encapsulate(kem.publicKey);
        final shared = await PqXWing.decapsulate(
          encapsulated.ciphertext,
          kem.secretKey,
        );
        expect(shared.length, 32);
        expect(shared, encapsulated.sharedSecret);

        final bobKey = await RatchetKeyPair.generate();
        final alice = await DoubleRatchet.initiate(
          sharedSecret: SharedSecret32(shared),
          remoteRatchetKey: bobKey.publicKey,
        );
        final bob = DoubleRatchet.accept(
          sharedSecret: SharedSecret32(shared),
          ratchetKey: bobKey,
        );
        expect(await bob.open(alice.seal(_text('xwing'))), _text('xwing'));

        expect(() => SharedSecret32(kem.publicKey), throwsArgumentError);
        expect(() => RatchetPublicKey(kem.publicKey), throwsArgumentError);
        expect(
          () => PqRatchetSecrets.copy32('rootKey', Uint8List(2400)),
          throwsA(isA<PqForgeException>()),
        );
        expect(
          () => PqRatchetSecrets.copy32('rootKey', Uint8List(1632)),
          throwsA(isA<PqForgeException>()),
        );
        expect(
          () => PqRatchetSecrets.copy32('rootKey', Uint8List(3168)),
          throwsA(isA<PqForgeException>()),
        );
      },
    );

    test('ChaCha20-Poly1305 and SHA-512 sessions round-trip', () async {
      for (final hash in DoubleRatchetHash.values) {
        for (final suite in PqForgeCipherSuite.values) {
          final parties = await _pair(hash: hash, suite: suite);
          final alice = parties.$1;
          final bob = parties.$2;
          final aad = _text('suite');
          expect(
            await bob.open(alice.seal(_text('body'), aad: aad), aad: aad),
            _text('body'),
          );
          expect(
            await alice.open(bob.seal(_text('back'), aad: aad), aad: aad),
            _text('back'),
          );
          if (hash == DoubleRatchetHash.sha512) {
            final oldChain = bob.copySendingChainKey()!;
            expect(await bob.open(alice.seal(_text('step'))), _text('step'));
            final newChain = bob.copySendingChainKey()!;
            expect(
              newChain,
              isNot(_hmac32(oldChain, 0x02, DoubleRatchetHash.sha512)),
            );
          }
        }
      }
    });

    test(
      'FIPS mode refuses ChaCha20-Poly1305 and still allows AES-256-GCM',
      () async {
        final secret = SharedSecret32(_pattern(32, 3));
        final bobKey = await RatchetKeyPair.generate();
        final chacha = DoubleRatchet.accept(
          sharedSecret: secret,
          ratchetKey: bobKey,
          suite: PqForgeCipherSuite.chaCha20Poly1305,
        );
        final encoded = chacha.toBytes();
        PqFipsMode.enable();
        try {
          expect(
            () => DoubleRatchet.accept(
              sharedSecret: secret,
              ratchetKey: bobKey,
              suite: PqForgeCipherSuite.chaCha20Poly1305,
            ),
            throwsA(isA<PqForgeException>()),
          );
          expect(
            () => DoubleRatchet.fromBytes(encoded),
            throwsA(isA<PqForgeException>()),
          );
          final aes = DoubleRatchet.accept(
            sharedSecret: secret,
            ratchetKey: bobKey,
          );
          expect(aes.suite, PqForgeCipherSuite.aes256Gcm);
          aes.dispose();
        } finally {
          PqFipsMode.disable();
        }
        final restored = DoubleRatchet.fromBytes(encoded);
        expect(restored.suite, PqForgeCipherSuite.chaCha20Poly1305);
        restored.dispose();
        chacha.dispose();
      },
    );

    test(
      'toBytes restores skipped keys, and a bad tag consumes the key',
      () async {
        final parties = await _pair(info: _text('pqforge-session'));
        final alice = parties.$1;
        final bob = parties.$2;
        final messages = [
          alice.seal(_text('a')),
          alice.seal(_text('b')),
          alice.seal(_text('c')),
        ];
        expect(await bob.open(messages[2]), _text('c'));
        expect(bob.skippedCount, 2);

        final copy = DoubleRatchet.fromBytes(bob.toBytes());
        expect(copy.skippedCount, 2);
        expect(await copy.open(messages[0]), _text('a'));
        expect(await copy.openBytes(messages[1].bytes), _text('b'));
        expect(copy.skippedCount, 0);

        final next = alice.seal(_text('d'));
        final flipped = Uint8List.fromList(next.bytes);
        flipped[flipped.length - 1] ^= 0x01;
        await expectLater(
          copy.openBytes(flipped),
          throwsA(isA<PqForgeAuthTagException>()),
        );
        await expectLater(
          copy.open(next),
          throwsA(isA<PqForgeAuthTagException>()),
        );

        final trailing = Uint8List(bob.toBytes().length + 1)
          ..setRange(0, bob.toBytes().length, bob.toBytes());
        expect(
          () => DoubleRatchet.fromBytes(trailing),
          throwsA(isA<PqForgeException>()),
        );
        expect(
          () => DoubleRatchet.fromBytes(Uint8List(8)),
          throwsA(isA<PqForgeException>()),
        );
      },
    );

    test('a different HKDF info does not open', () async {
      final secret = SharedSecret32(_pattern(32, 4));
      final bobKey = await RatchetKeyPair.generate();
      final alice = await DoubleRatchet.initiate(
        sharedSecret: secret,
        remoteRatchetKey: bobKey.publicKey,
        info: _text('one'),
      );
      final bob = DoubleRatchet.accept(
        sharedSecret: secret,
        ratchetKey: bobKey,
        info: _text('two'),
      );
      await expectLater(
        bob.open(alice.seal(_text('no'))),
        throwsA(isA<PqForgeAuthTagException>()),
      );
    });

    test(
      'associated data is the caller bytes in front of the header',
      () async {
        final parties = await _pair();
        final alice = parties.$1;
        final bob = parties.$2;
        final sealed = alice.seal(_text('plain'), aad: Uint8List(0));
        expect(await bob.open(sealed), _text('plain'));
        final withAad = alice.seal(_text('bound'), aad: _text('aad'));
        await expectLater(
          bob.open(withAad),
          throwsA(isA<PqForgeAuthTagException>()),
        );
      },
    );
  });

  group('PQXDH and Triple Ratchet scaffolds', () {
    test('PQXDH throws, and a 1216-byte key is not a bundle field', () async {
      final identity = await RatchetKeyPair.generate();
      final bundle = PqxdhBundle(
        identityKey: identity.publicKey,
        signedPrekey: identity.publicKey,
        signedPrekeySignature: Uint8List(64),
        kemPublicKey: Uint8List(PqxdhKem.kyber1024.publicKeyBytes),
      );
      await expectLater(
        Pqxdh.initiate(identityKey: identity, bundle: bundle),
        throwsA(isA<PqForgeException>()),
      );
      final initial = DoubleRatchetMessage.parse(
        Uint8List(DoubleRatchetMessage.headerBytes + 16),
      );
      await expectLater(
        Pqxdh.accept(
          identityKey: identity,
          signedPrekey: identity,
          bundle: bundle,
          initialMessage: initial,
        ),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        () => PqxdhBundle(
          identityKey: identity.publicKey,
          signedPrekey: identity.publicKey,
          signedPrekeySignature: Uint8List(64),
          kemPublicKey: Uint8List(1216),
        ),
        throwsArgumentError,
      );
      expect(
        () => PqxdhBundle(
          identityKey: identity.publicKey,
          signedPrekey: identity.publicKey,
          signedPrekeySignature: Uint8List(1216),
          kemPublicKey: Uint8List(PqxdhKem.kyber1024.publicKeyBytes),
        ),
        throwsArgumentError,
      );
    });

    test('TripleRatchet.initiate throws after the 32-byte checks', () async {
      final remote = await RatchetKeyPair.generate();
      await expectLater(
        TripleRatchet.initiate(
          sharedSecret: SharedSecret32(_pattern(32, 9)),
          remoteRatchetKey: remote.publicKey,
        ),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        () => TripleRatchet.initiate(
          sharedSecret: SharedSecret32(Uint8List(32)),
          remoteRatchetKey: RatchetPublicKey(Uint8List(1216)),
        ),
        throwsArgumentError,
      );
    });
  });
}

Future<(DoubleRatchet, DoubleRatchet)> _pair({
  int maxSkip = DoubleRatchet.defaultMaxSkip,
  DoubleRatchetHash hash = DoubleRatchetHash.sha256,
  PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
  Uint8List? info,
}) async {
  final secret = SharedSecret32(
    _pattern(32, maxSkip + suite.index + hash.index),
  );
  final bobKey = await RatchetKeyPair.generate();
  final alice = await DoubleRatchet.initiate(
    sharedSecret: secret,
    remoteRatchetKey: bobKey.publicKey,
    hash: hash,
    suite: suite,
    info: info,
    maxSkip: maxSkip,
  );
  final bob = DoubleRatchet.accept(
    sharedSecret: secret,
    ratchetKey: bobKey,
    hash: hash,
    suite: suite,
    info: info,
    maxSkip: maxSkip,
  );
  return (alice, bob);
}

Uint8List _pattern(int length, int seed) => Uint8List.fromList(
  List<int>.generate(length, (i) => (seed + i * 17) & 0xff),
);

Uint8List _text(String value) => Uint8List.fromList(value.codeUnits);

Uint8List _hmac32(Uint8List key, int constant, DoubleRatchetHash hash) {
  final input = Uint8List.fromList([constant]);
  final full = switch (hash) {
    DoubleRatchetHash.sha256 => pqc.hmacSha256(key, input),
    DoubleRatchetHash.sha512 => pqc.hmacSha512(key, input),
  };
  if (full.length == 32) return full;
  return Uint8List(32)..setRange(0, 32, full);
}
