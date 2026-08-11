import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

/// R5: multi-recipient encryption — the payload is sealed exactly once and the
/// DEM key is wrapped to each additional recipient in `recipients[]` metadata.
/// No wire-format change; works for one-shot envelopes and `.pqfs` containers;
/// entries can themselves be hybrid (per-recipient X25519).
void main() {
  const forge = PqForge(profile: PqForgeProfile.compact);
  late PqKeyBundle alice; // primary
  late PqKeyBundle bob; // additional, post-quantum-only entry
  late PqKeyBundle carol; // additional, hybrid entry
  late PqKeyBundle mallory; // not a recipient

  setUp(() {
    alice = forge.generateKeys(keyId: 'alice');
    bob = forge.generateKeys(keyId: 'bob');
    carol = forge.generateKeys(keyId: 'carol');
    mallory = forge.generateKeys(keyId: 'mallory');
  });

  Uint8List payload(int n) =>
      Uint8List.fromList(List<int>.generate(n, (i) => (i * 31 + 7) & 0xFF));

  group('one-shot multi-recipient envelopes', () {
    test('every recipient opens the single sealed payload', () async {
      final plaintext = payload(4096);
      final kexCarol = await const PqForgeHybridKeyAgreement()
          .generateClassicalKeyPairBytes();
      final envelope = await forge.encryptAsync(
        alice.kemKeyPair.publicKey,
        plaintext,
        recipientKeyId: 'alice',
        additionalRecipients: [
          PqRecipientSpec(kemPublicKey: bob.kemKeyPair.publicKey, keyId: 'bob'),
          PqRecipientSpec(
            kemPublicKey: carol.kemKeyPair.publicKey,
            kexPublicKey: kexCarol.publicKey,
            keyId: 'carol',
          ),
        ],
      );
      expect(PqMultiRecipient.hasEntries(envelope.metadata), isTrue);
      expect(envelope.metadata[pqForgeRecipientKeyIdMetadataKey], 'alice');
      final entries = PqMultiRecipient.parseEntries(envelope.metadata);
      expect(entries, hasLength(2));
      expect(entries.first.keyId, 'bob');
      expect(entries.first.ephemeralPublicKey, isNull);
      expect(entries.last.keyId, 'carol');
      expect(entries.last.ephemeralPublicKey, hasLength(32));

      expect(
        await forge.decryptAsync(
          alice.kemKeyPair.secretKey,
          envelope,
          recipientKeyId: 'alice',
        ),
        plaintext,
      );
      expect(
        await forge.decryptAsync(
          bob.kemKeyPair.secretKey,
          envelope,
          recipientKeyId: 'bob',
        ),
        plaintext,
      );
      // No key-id hint: the trial order still finds bob's entry.
      expect(
        await forge.decryptAsync(bob.kemKeyPair.secretKey, envelope),
        plaintext,
      );
      expect(
        await forge.decryptAsync(
          carol.kemKeyPair.secretKey,
          envelope,
          recipientKeyId: 'carol',
          recipientKexSecretKey: kexCarol.secretKey,
        ),
        plaintext,
      );
    });

    test(
      'a hybrid primary never blocks a plain additional recipient',
      () async {
        final plaintext = payload(512);
        final kexAlice = await const PqForgeHybridKeyAgreement()
            .generateClassicalKeyPairBytes();
        final envelope = await forge.encryptAsync(
          alice.kemKeyPair.publicKey,
          plaintext,
          recipientKexPublicKey: kexAlice.publicKey,
          recipientKeyId: 'alice',
          additionalRecipients: [
            PqRecipientSpec(
              kemPublicKey: bob.kemKeyPair.publicKey,
              keyId: 'bob',
            ),
          ],
        );
        expect(PqHybridKemDem.isHybrid(envelope.metadata), isTrue);
        // Bob holds no X25519 key at all: the hybrid-primary requirement is
        // deferred and his recipients[] entry still opens the payload.
        expect(
          await forge.decryptAsync(
            bob.kemKeyPair.secretKey,
            envelope,
            recipientKeyId: 'bob',
          ),
          plaintext,
        );
        // The primary still needs (and works with) her kex secret.
        expect(
          await forge.decryptAsync(
            alice.kemKeyPair.secretKey,
            envelope,
            recipientKexSecretKey: kexAlice.secretKey,
            recipientKeyId: 'alice',
          ),
          plaintext,
        );
      },
    );

    test('a non-recipient key gets the descriptive error', () async {
      final envelope = await forge.encryptAsync(
        alice.kemKeyPair.publicKey,
        payload(64),
        recipientKeyId: 'alice',
        additionalRecipients: [
          PqRecipientSpec(kemPublicKey: bob.kemKeyPair.publicKey, keyId: 'bob'),
        ],
      );
      await expectLater(
        forge.decryptAsync(
          mallory.kemKeyPair.secretKey,
          envelope,
          recipientKeyId: 'mallory',
        ),
        throwsA(
          isA<PqForgeException>().having(
            (e) => e.message,
            'message',
            contains('not addressed'),
          ),
        ),
      );
    });

    test('a hybrid wrap entry is skipped without its X25519 key', () async {
      final kexCarol = await const PqForgeHybridKeyAgreement()
          .generateClassicalKeyPairBytes();
      final envelope = await forge.encryptAsync(
        alice.kemKeyPair.publicKey,
        payload(64),
        recipientKeyId: 'alice',
        additionalRecipients: [
          PqRecipientSpec(
            kemPublicKey: carol.kemKeyPair.publicKey,
            kexPublicKey: kexCarol.publicKey,
            keyId: 'carol',
          ),
        ],
      );
      await expectLater(
        forge.decryptAsync(
          carol.kemKeyPair.secretKey,
          envelope,
          recipientKeyId: 'carol',
        ),
        throwsA(
          isA<PqForgeException>().having(
            (e) => e.message,
            'message',
            contains('not addressed'),
          ),
        ),
      );
    });

    test('signed multi-recipient roundtrip binds the entries', () async {
      final plaintext = payload(512);
      final envelope = await forge.encryptAsync(
        alice.kemKeyPair.publicKey,
        plaintext,
        recipientKeyId: 'alice',
        additionalRecipients: [
          PqRecipientSpec(kemPublicKey: bob.kemKeyPair.publicKey, keyId: 'bob'),
        ],
        signerSecretKey: alice.signatureKeyPair.secretKey,
      );
      expect(envelope.isSigned, isTrue);
      expect(
        await forge.decryptAsync(
          bob.kemKeyPair.secretKey,
          envelope,
          recipientKeyId: 'bob',
          signerPublicKey: alice.signatureKeyPair.publicKey,
        ),
        plaintext,
      );
    });

    test('sync decrypt: primary works, additional gets guidance', () async {
      final plaintext = payload(256);
      final envelope = await forge.encryptAsync(
        alice.kemKeyPair.publicKey,
        plaintext,
        recipientKeyId: 'alice',
        additionalRecipients: [
          PqRecipientSpec(kemPublicKey: bob.kemKeyPair.publicKey, keyId: 'bob'),
        ],
      );
      // The primary derivation is unchanged, so the sync path still opens it.
      expect(forge.decrypt(alice.kemKeyPair.secretKey, envelope), plaintext);
      // An additional recipient on the sync path gets pointed at decryptAsync
      // instead of an opaque tag failure.
      expect(
        () => forge.decrypt(bob.kemKeyPair.secretKey, envelope),
        throwsA(
          isA<PqForgeException>().having(
            (e) => e.message,
            'message',
            contains('decryptAsync'),
          ),
        ),
      );
    });

    test('caller metadata cannot spoof the reserved markers', () async {
      for (final reserved in pqForgeReservedMetadataKeys) {
        await expectLater(
          forge.encryptAsync(
            alice.kemKeyPair.publicKey,
            payload(16),
            metadata: {reserved: 'spoof'},
          ),
          throwsA(
            isA<PqForgeException>().having(
              (e) => e.message,
              'message',
              contains('reserved'),
            ),
          ),
        );
        expect(
          () => forge.encrypt(
            alice.kemKeyPair.publicKey,
            payload(16),
            metadata: {reserved: 'spoof'},
          ),
          throwsA(isA<PqForgeException>()),
        );
      }
    });

    test(
      'malformed recipients metadata surfaces as PqForgeException',
      () async {
        final envelope = await forge.encryptAsync(
          alice.kemKeyPair.publicKey,
          payload(64),
        );
        final mangled = PqEnvelope(
          profile: envelope.profile,
          kemAlgorithm: envelope.kemAlgorithm,
          kemCiphertext: envelope.kemCiphertext,
          nonce: envelope.nonce,
          payload: envelope.payload,
          metadata: {...envelope.metadata, 'recipients': 'bogus'},
        );
        await expectLater(
          forge.decryptAsync(bob.kemKeyPair.secretKey, mangled),
          throwsA(
            isA<PqForgeException>().having(
              (e) => e.message,
              'message',
              contains('Malformed recipients'),
            ),
          ),
        );
      },
    );
  });

  group('streaming multi-recipient containers', () {
    late Directory dir;

    setUp(() => dir = Directory.systemTemp.createTempSync('pqfs_multi_'));
    tearDown(() => dir.deleteSync(recursive: true));

    test('primary and additional both decrypt the same archive', () async {
      final original = payload(300 * 1024);
      final src = File('${dir.path}/in.bin')..writeAsBytesSync(original);
      final enc = File('${dir.path}/in.pqf');
      final cipher = PqForgeStreamCipher();

      await cipher.encryptFile(
        recipientPublicKey: alice.kemKeyPair.publicKey,
        additionalRecipients: [
          PqRecipientSpec(kemPublicKey: bob.kemKeyPair.publicKey, keyId: 'bob'),
        ],
        recipientKeyId: 'alice',
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
        signerSecretKey: alice.signatureKeyPair.secretKey,
        frameSize: 64 * 1024,
      );

      final header = await cipher.readHeader(enc);
      expect(PqMultiRecipient.hasEntries(header.metadata), isTrue);
      expect(header.metadata[pqForgeRecipientKeyIdMetadataKey], 'alice');

      final outAlice = File('${dir.path}/alice.bin');
      await cipher.decryptFile(
        recipientSecretKey: alice.kemKeyPair.secretKey,
        recipientKeyId: 'alice',
        input: enc,
        output: outAlice,
        signerPublicKey: alice.signatureKeyPair.publicKey,
      );
      expect(outAlice.readAsBytesSync(), original);

      final outBob = File('${dir.path}/bob.bin');
      await cipher.decryptFile(
        recipientSecretKey: bob.kemKeyPair.secretKey,
        recipientKeyId: 'bob',
        input: enc,
        output: outBob,
        signerPublicKey: alice.signatureKeyPair.publicKey,
      );
      expect(outBob.readAsBytesSync(), original);
    });

    test('a non-recipient key fails with the descriptive error', () async {
      final src = File('${dir.path}/in.bin')..writeAsBytesSync(payload(1024));
      final enc = File('${dir.path}/in.pqf');
      final cipher = PqForgeStreamCipher();
      await cipher.encryptFile(
        recipientPublicKey: alice.kemKeyPair.publicKey,
        additionalRecipients: [
          PqRecipientSpec(kemPublicKey: bob.kemKeyPair.publicKey, keyId: 'bob'),
        ],
        recipientKeyId: 'alice',
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
      );
      final out = File('${dir.path}/out.bin');
      await expectLater(
        cipher.decryptFile(
          recipientSecretKey: mallory.kemKeyPair.secretKey,
          recipientKeyId: 'mallory',
          input: enc,
          output: out,
        ),
        throwsA(
          isA<PqForgeException>().having(
            (e) => e.message,
            'message',
            contains('not addressed'),
          ),
        ),
      );
      expect(out.existsSync(), isFalse);
    });
  });
}
