import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

/// PQXDH, then a header-encrypted Double Ratchet, framed as CV01.
///
/// The default [ConversationLevel] is ML-KEM-1024, ML-DSA-65, AES-256-GCM.
/// [ConversationLevel.compact], [ConversationLevel.balanced],
/// [ConversationLevel.maximum], and [ConversationLevel.hashBased] are the
/// other built-in choices. [ConversationLevel.hash] takes any SLH-DSA set.
/// The hash-based signature is on the bundle, once. Messages stay AEAD.
Future<void> main() async {
  final identity = PqSignaturePrimitives.generateKeyPair(
    PqSignatureAlgorithm.mlDsa65,
  );
  final bob = await Pqxdh.publish(
    signedPrekeyId: 7,
    oneTimePrekeyId: 9,
    oneTimePrekey: true,
    trustKey: identity,
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
    offload: false,
  );
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
  print('opened: ${utf8.decode(accepted.plaintext)}');
  final sealed = await started.session.seal(_text('next'), messageId: 'm1');
  print('header encrypted: ${_has(sealed, const [0x44, 0x52, 0x48, 0x31])}');
  print(
    'reply: ${utf8.decode(await accepted.session.open(sealed, messageId: 'm1'))}',
  );
  final restored = await ConversationSession.fromBytes(
    accepted.session.toBytes(),
  );
  final again = await started.session.seal(_text('back'), messageId: 'm2');
  print(
    'restored: ${utf8.decode(await restored.open(again, messageId: 'm2'))}',
  );
  started.session.wipe();
  accepted.session.wipe();
  restored.wipe();
  bob.wipe();
  aliceKey.wipe();
}

Uint8List _text(String value) => Uint8List.fromList(utf8.encode(value));

bool _has(Uint8List bytes, List<int> needle) {
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
