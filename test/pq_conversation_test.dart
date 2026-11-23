import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  test('encrypted Double Ratchet headers round-trip', () async {
    final bobKey = await RatchetKeyPair.generate();
    final secret = SharedSecret32(Uint8List(32)..fillRange(0, 32, 7));
    final alice = await DoubleRatchet.initiate(
      sharedSecret: secret,
      remoteRatchetKey: bobKey.publicKey,
      encryptHeaders: true,
    );
    final bob = DoubleRatchet.accept(
      sharedSecret: secret,
      ratchetKey: bobKey,
      encryptHeaders: true,
    );
    final first = alice.seal(Uint8List.fromList(const [1, 2, 3]));
    expect(first.headerEncrypted, isTrue);
    expect(first.bytes.sublist(0, 4), [0x44, 0x52, 0x48, 0x31]);
    expect(await bob.open(first), [1, 2, 3]);
    final reply = bob.seal(Uint8List.fromList(const [4, 5]));
    expect(await alice.open(reply), [4, 5]);
    final restored = DoubleRatchet.fromBytes(alice.toBytes());
    final third = bob.seal(Uint8List.fromList(const [6]));
    expect(await restored.open(third), [6]);
    alice.dispose();
    bob.dispose();
    restored.dispose();
    bobKey.wipe();
  });

  test('conversation keeps the chosen ratchet and an ML-DSA bundle', () async {
    final identity = PqSignaturePrimitives.generateKeyPair(
      PqSignatureAlgorithm.mlDsa65,
    );
    final bob = await Pqxdh.publish(
      oneTimePrekey: true,
      signedPrekeyId: 7,
      oneTimePrekeyId: 9,
      trustKey: identity,
    );
    expect(Pqxdh.mlDsaAuthentic(bob.bundle), isTrue);
    final aliceKey = await RatchetKeyPair.generate();
    final started = await ConversationSession.start(
      conversationId: 'desk',
      ratchet: ConversationRatchet.doubleRatchet,
      identityKey: aliceKey,
      bundle: bob.bundle,
      plaintext: _text('hello'),
      messageId: 'm0',
      trustPublicKey: identity.publicKey,
      offload: false,
    );
    expect(started.message.sublist(0, 4), [0x43, 0x56, 0x30, 0x31]);
    final accepted = await ConversationSession.accept(
      conversationId: 'desk',
      identityKey: bob.identityKey,
      signedPrekey: bob.signedPrekey,
      kemSecretKey: bob.kemSecretKey,
      oneTimePrekey: bob.oneTimePrekey,
      message: started.message,
      messageId: 'm0',
      trustPublicKey: identity.publicKey,
      ratchet: ConversationRatchet.doubleRatchet,
      offload: false,
    );
    expect(utf8.decode(accepted.plaintext), 'hello');
    final sealed = await started.session.seal(_text('next'), messageId: 'm1');
    expect(_contains(sealed, const [0x44, 0x52, 0x48, 0x31]), isTrue);
    expect(
      utf8.decode(await accepted.session.open(sealed, messageId: 'm1')),
      'next',
    );
    final restored = await ConversationSession.fromBytes(
      accepted.session.toBytes(),
    );
    final reply = await started.session.seal(_text('back'), messageId: 'm2');
    expect(utf8.decode(await restored.open(reply, messageId: 'm2')), 'back');
    started.session.wipe();
    accepted.session.wipe();
    restored.wipe();
    bob.wipe();
    aliceKey.wipe();
  });

  test(
    'triple ratchet conversation restores without the expanded key',
    () async {
      final identity = PqSignaturePrimitives.generateKeyPair(
        PqSignatureAlgorithm.mlDsa65,
      );
      final bob = await Pqxdh.publish(signedPrekeyId: 3, trustKey: identity);
      final aliceKey = await RatchetKeyPair.generate();
      final started = await ConversationSession.start(
        conversationId: 'vault',
        ratchet: ConversationRatchet.tripleRatchet,
        identityKey: aliceKey,
        bundle: bob.bundle,
        plaintext: _text('open'),
        messageId: 'm0',
        trustPublicKey: identity.publicKey,
        chunksPerMessage: 4,
        offload: false,
      );
      final accepted = await ConversationSession.accept(
        conversationId: 'vault',
        ratchet: ConversationRatchet.tripleRatchet,
        identityKey: bob.identityKey,
        signedPrekey: bob.signedPrekey,
        kemSecretKey: bob.kemSecretKey,
        message: started.message,
        messageId: 'm0',
        trustPublicKey: identity.publicKey,
        offload: false,
      );
      expect(utf8.decode(accepted.plaintext), 'open');
      final sealed = await started.session.seal(
        _text('epoch'),
        messageId: 'm1',
      );
      expect(_contains(sealed, const [0x54, 0x52, 0x48, 0x31]), isTrue);
      expect(
        utf8.decode(await accepted.session.open(sealed, messageId: 'm1')),
        'epoch',
      );
      final record = started.session.toBytes();
      expect(record.length, lessThan(8192));
      expect(_hasLength(record, 2400), isFalse);
      final restored = await ConversationSession.fromBytes(
        record,
        offload: false,
      );
      final second = await restored.seal(_text('again'), messageId: 'm2');
      expect(
        utf8.decode(await accepted.session.open(second, messageId: 'm2')),
        'again',
      );
      started.session.wipe();
      accepted.session.wipe();
      restored.wipe();
      bob.wipe();
      aliceKey.wipe();
    },
  );

  test('a bundle without ML-DSA is refused', () async {
    final bob = await Pqxdh.publish(signedPrekeyId: 1);
    final aliceKey = await RatchetKeyPair.generate();
    expect(
      ConversationSession.start(
        conversationId: 'desk',
        ratchet: ConversationRatchet.doubleRatchet,
        identityKey: aliceKey,
        bundle: bob.bundle,
        plaintext: _text('no'),
        messageId: 'm0',
        trustPublicKey: Uint8List(32),
      ),
      throwsA(isA<PqForgeException>()),
    );
    bob.wipe();
    aliceKey.wipe();
  });

  test('a pin that is not the bundle key derives nothing', () async {
    final identity = PqSignaturePrimitives.generateKeyPair(
      PqSignatureAlgorithm.mlDsa65,
    );
    final bob = await Pqxdh.publish(
      signedPrekeyId: 1,
      trustKey: identity,
      offload: false,
    );
    final aliceKey = await RatchetKeyPair.generate();
    final wrong = Uint8List.fromList(identity.publicKey)..[0] ^= 1;
    expect(
      ConversationSession.start(
        conversationId: 'desk',
        ratchet: ConversationRatchet.doubleRatchet,
        identityKey: aliceKey,
        bundle: bob.bundle,
        plaintext: _text('no'),
        messageId: 'm0',
        trustPublicKey: wrong,
        offload: false,
      ),
      throwsA(isA<PqForgeException>()),
    );
    bob.wipe();
    aliceKey.wipe();
  });

  test(
    'a flipped ratchet byte is rejected before the session starts',
    () async {
      final identity = PqSignaturePrimitives.generateKeyPair(
        PqSignatureAlgorithm.mlDsa44,
      );
      const level = ConversationLevel.compact;
      final bob = await Pqxdh.publish(
        signedPrekeyId: 4,
        kem: level.kem,
        trust: level.trust,
        trustKey: identity,
        offload: false,
      );
      final aliceKey = await RatchetKeyPair.generate();
      final started = await ConversationSession.start(
        conversationId: 'desk',
        ratchet: ConversationRatchet.doubleRatchet,
        identityKey: aliceKey,
        bundle: bob.bundle,
        plaintext: _text('hello'),
        messageId: 'm0',
        trustPublicKey: identity.publicKey,
        level: level,
        offload: false,
      );
      final flipped = Uint8List.fromList(started.message)..[5] = 2;
      expect(
        ConversationSession.accept(
          conversationId: 'desk',
          ratchet: ConversationRatchet.doubleRatchet,
          identityKey: bob.identityKey,
          signedPrekey: bob.signedPrekey,
          kemSecretKey: bob.kemSecretKey,
          message: flipped,
          messageId: 'm0',
          trustPublicKey: identity.publicKey,
          level: level,
          offload: false,
        ),
        throwsA(isA<PqForgeException>()),
      );
      final opened = await ConversationSession.accept(
        conversationId: 'desk',
        ratchet: ConversationRatchet.doubleRatchet,
        identityKey: bob.identityKey,
        signedPrekey: bob.signedPrekey,
        kemSecretKey: bob.kemSecretKey,
        message: started.message,
        messageId: 'm0',
        trustPublicKey: identity.publicKey,
        level: level,
        offload: false,
      );
      expect(utf8.decode(opened.plaintext), 'hello');
      started.session.wipe();
      opened.session.wipe();
      bob.wipe();
      aliceKey.wipe();
    },
  );

  test('hash levels match the profile SLH-DSA sets', () {
    expect(
      ConversationLevel.fromProfile(PqForgeProfile.compact, hash: true).trust,
      ConversationLevel.hashCompact.trust,
    );
    expect(
      ConversationLevel.fromProfile(PqForgeProfile.balanced, hash: true).trust,
      ConversationLevel.hashBalanced.trust,
    );
    expect(
      ConversationLevel.fromProfile(PqForgeProfile.maximum, hash: true).trust,
      ConversationLevel.hashMaximum.trust,
    );
    expect(ConversationLevel.hashBased.trust, PqxdhTrust.shake128f);
    expect(ConversationLevel.hashBased.kem, PqxdhKem.kyber1024);
    expect(ConversationLevel.hashCompact.kem, PqxdhKem.mlKem512);
  });

  test(
    'SLH-DSA-SHAKE-128f is a bundle identity, not a message signature',
    () async {
      final identity = PqSlhDsaPrimitives.generateKeyPair(
        PqSlhDsaAlgorithm.shake128f,
      );
      const level = ConversationLevel.hashBased;
      final bob = await Pqxdh.publish(
        signedPrekeyId: 11,
        kem: level.kem,
        trust: level.trust,
        trustKey: identity,
        offload: false,
      );
      expect(bob.bundle.trustSignature!.length, level.trust.signatureBytes);
      expect(await Pqxdh.trustAuthentic(bob.bundle, offload: false), isTrue);
      final aliceKey = await RatchetKeyPair.generate();
      final started = await ConversationSession.start(
        conversationId: 'hash',
        ratchet: ConversationRatchet.doubleRatchet,
        identityKey: aliceKey,
        bundle: bob.bundle,
        plaintext: _text('once'),
        messageId: 'm0',
        trustPublicKey: identity.publicKey,
        level: level,
        offload: false,
      );
      final accepted = await ConversationSession.accept(
        conversationId: 'hash',
        ratchet: ConversationRatchet.doubleRatchet,
        identityKey: bob.identityKey,
        signedPrekey: bob.signedPrekey,
        kemSecretKey: bob.kemSecretKey,
        message: started.message,
        messageId: 'm0',
        trustPublicKey: identity.publicKey,
        level: level,
        offload: false,
      );
      expect(utf8.decode(accepted.plaintext), 'once');
      final sealed = await started.session.seal(_text('next'), messageId: 'm1');
      expect(sealed.length, lessThan(level.trust.signatureBytes));
      expect(
        utf8.decode(await accepted.session.open(sealed, messageId: 'm1')),
        'next',
      );
      started.session.wipe();
      accepted.session.wipe();
      bob.wipe();
      aliceKey.wipe();
    },
  );
}

Uint8List _text(String value) => Uint8List.fromList(utf8.encode(value));

bool _contains(Uint8List bytes, List<int> needle) {
  for (var i = 0; i + needle.length <= bytes.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (bytes[i + j] != needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

bool _hasLength(Uint8List bytes, int length) {
  if (bytes.length < 4) return false;
  final data = ByteData.sublistView(bytes);
  for (var i = 0; i + 4 <= bytes.length; i++) {
    if (data.getUint32(i) == length) return true;
  }
  return false;
}
