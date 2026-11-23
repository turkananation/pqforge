/// Direct conversation recipe.
///
/// PQXDH revision 3, then either a Double Ratchet or a Triple Ratchet.
/// The caller chooses the ratchet, the KEM, the AEAD, and the trust
/// identity. None of those are negotiated from the wire. Both sessions
/// encrypt headers. The Triple Ratchet attaches four braid chunks to
/// each message unless the caller says otherwise.
///
/// The bundle's trust decision is one signature: ML-DSA-44, ML-DSA-65,
/// ML-DSA-87, or any of the twelve SLH-DSA sets. XEdDSA still has to
/// pass inside PQXDH. That signature is not mixed into SK. The hash-based
/// signature sits on the bundle, once. It is not repeated on messages.
/// This is not Signal, not libsignal bytes, and not a FIPS handshake.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:zeroize/zeroize.dart';

import '../algorithms/pq_algorithms.dart';
import '../cipher/pq_cipher_suite.dart';
import '../exceptions/pqforge_exception.dart';
import 'pq_double_ratchet.dart';
import 'pq_pqxdh.dart';
import 'pq_ratchet_types.dart';
import 'pq_triple_ratchet.dart';

/// Which session [ConversationSession] keeps after PQXDH.
enum ConversationRatchet {
  /// X25519 Double Ratchet. Header encryption is on. Healing is classical.
  doubleRatchet,

  /// X25519 plus the ML-KEM-768 braid. Header encryption is on.
  tripleRatchet,
}

/// KEM, trust identity, and AEAD for one conversation.
///
/// Both sides pass the same value. The wire does not offer a menu.
/// [compact], [balanced], and [maximum] are the ML-DSA identities and
/// match [PqForgeProfile]. [hashCompact], [hashBalanced], and
/// [hashMaximum] are the same KEMs with the profile's fast SLH-DSA set.
/// [hashBased] is the fastest hash identity: ML-KEM-1024 and
/// SLH-DSA-SHAKE-128f. [hashMaximum] matches category 5 and costs a
/// larger, slower signature. The default is ML-KEM-1024, ML-DSA-65,
/// and AES-256-GCM. Pass any of the twelve sets to [hash].
final class ConversationLevel {
  /// Default handshake: ML-KEM-1024, ML-DSA-65, AES-256-GCM.
  const ConversationLevel({
    this.kem = PqxdhKem.kyber1024,
    this.trust = PqxdhTrust.mlDsa65,
    this.suite = PqForgeCipherSuite.aes256Gcm,
  });

  /// ML-KEM-512 and ML-DSA-44.
  static const compact = ConversationLevel(
    kem: PqxdhKem.mlKem512,
    trust: PqxdhTrust.mlDsa44,
  );

  /// ML-KEM-768 and ML-DSA-65.
  static const balanced = ConversationLevel(
    kem: PqxdhKem.mlKem768,
    trust: PqxdhTrust.mlDsa65,
  );

  /// ML-KEM-1024 and ML-DSA-87.
  static const maximum = ConversationLevel(
    kem: PqxdhKem.kyber1024,
    trust: PqxdhTrust.mlDsa87,
  );

  /// ML-KEM-512 and SLH-DSA-SHAKE-128f. The fast compact hash identity.
  static const hashCompact = ConversationLevel(
    kem: PqxdhKem.mlKem512,
    trust: PqxdhTrust.shake128f,
  );

  /// ML-KEM-768 and SLH-DSA-SHAKE-192f.
  static const hashBalanced = ConversationLevel(
    kem: PqxdhKem.mlKem768,
    trust: PqxdhTrust.shake192f,
  );

  /// ML-KEM-1024 and SLH-DSA-SHAKE-256f. Category match. Slower to sign.
  static const hashMaximum = ConversationLevel(
    kem: PqxdhKem.kyber1024,
    trust: PqxdhTrust.shake256f,
  );

  /// ML-KEM-1024 and SLH-DSA-SHAKE-128f. The fast hash-based identity.
  static const hashBased = ConversationLevel(trust: PqxdhTrust.shake128f);

  /// Lattice or hash identity for [profile]. [hash] selects `profile.slhDsa`.
  factory ConversationLevel.fromProfile(
    PqForgeProfile profile, {
    bool hash = false,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
  }) {
    final kem = switch (profile.kem) {
      PqKemAlgorithm.mlKem512 => PqxdhKem.mlKem512,
      PqKemAlgorithm.mlKem768 => PqxdhKem.mlKem768,
      PqKemAlgorithm.mlKem1024 => PqxdhKem.kyber1024,
    };
    return ConversationLevel(
      kem: kem,
      trust: hash
          ? PqxdhTrust.slhDsa(profile.slhDsa)
          : PqxdhTrust.mlDsa(profile.signature),
      suite: suite,
    );
  }

  /// Any of the twelve SLH-DSA sets. An `s` set is valid and slow.
  factory ConversationLevel.hash(
    PqSlhDsaAlgorithm algorithm, {
    PqxdhKem kem = PqxdhKem.kyber1024,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
  }) => ConversationLevel(
    kem: kem,
    trust: PqxdhTrust.slhDsa(algorithm),
    suite: suite,
  );

  /// Handshake KEM. Not the braid KEM. The braid stays ML-KEM-768.
  final PqxdhKem kem;

  /// Bundle signature. Not an input to SK.
  final PqxdhTrust trust;

  /// AEAD for the handshake and the ratchet.
  final PqForgeCipherSuite suite;
}

/// What [ConversationSession.start] returns.
final class ConversationStarted {
  ConversationStarted(this.session, this.message, this.plaintext);

  final ConversationSession session;

  /// `CV01` bytes. Send these.
  final Uint8List message;

  /// The plaintext Alice sealed under SK.
  final Uint8List plaintext;
}

/// What [ConversationSession.accept] returns.
final class ConversationAccepted {
  ConversationAccepted(this.session, this.plaintext);

  final ConversationSession session;
  final Uint8List plaintext;
}

/// One direct conversation.
final class ConversationSession {
  ConversationSession._({
    required this.conversationId,
    required this.ratchet,
    required DoubleRatchet? elliptic,
    required TripleRatchet? triple,
    required this.suite,
  }) : _elliptic = elliptic,
       _triple = triple;

  /// Alice. [trustPublicKey] is the identity the app already trusts.
  /// It is not the key that arrived in the same directory response unless
  /// the app pinned that key some other way. [level] is the KEM, the
  /// trust algorithm, and the AEAD. [plaintext] is the first message,
  /// sealed under SK, not under a ratchet key. Later messages use [seal].
  static Future<ConversationStarted> start({
    required String conversationId,
    required ConversationRatchet ratchet,
    required RatchetKeyPair identityKey,
    required PqxdhBundle bundle,
    required Uint8List plaintext,
    required String messageId,
    required Uint8List trustPublicKey,
    ConversationLevel level = const ConversationLevel(),
    int chunksPerMessage = 4,
    bool offload = true,
  }) async {
    _requireText(conversationId, 'conversationId');
    _requireText(messageId, 'messageId');
    await _requirePinned(bundle, level, trustPublicKey, offload: offload);
    final handshake = await Pqxdh.initiate(
      identityKey: identityKey,
      bundle: bundle,
      plaintext: plaintext,
      extraAssociatedData: _associated(
        conversationId: conversationId,
        messageId: messageId,
        ratchet: ratchet,
        level: level,
        trustPublicKey: trustPublicKey,
      ),
      suite: level.suite,
      kem: level.kem,
      offload: offload,
    );
    try {
      final session = await _afterHandshake(
        secret: handshake.sharedSecret,
        conversationId: conversationId,
        ratchet: ratchet,
        remote: bundle.signedPrekey,
        local: null,
        suite: level.suite,
        chunksPerMessage: chunksPerMessage,
        offload: offload,
      );
      return ConversationStarted(
        session,
        _frame(ratchet, conversationId, handshake.initialMessage!.bytes),
        handshake.plaintext,
      );
    } finally {
      handshake.ratchet.dispose();
      secureZero(handshake.sharedSecret.bytes);
    }
  }

  /// Bob. [ratchet] is the session both sides agreed. The wire byte has
  /// to match it. The session is built from [ratchet], not from that byte.
  /// [trustPublicKey] is Bob's own identity, the same pin Alice used.
  static Future<ConversationAccepted> accept({
    required String conversationId,
    required ConversationRatchet ratchet,
    required RatchetKeyPair identityKey,
    required RatchetKeyPair signedPrekey,
    required Uint8List kemSecretKey,
    required Uint8List message,
    required String messageId,
    required Uint8List trustPublicKey,
    RatchetKeyPair? oneTimePrekey,
    ConversationLevel level = const ConversationLevel(),
    int chunksPerMessage = 4,
    bool offload = true,
  }) async {
    _requireText(conversationId, 'conversationId');
    _requireText(messageId, 'messageId');
    if (trustPublicKey.length != level.trust.publicKeyBytes) {
      throw const PqForgeException(
        'Conversation identity does not match the pinned key. No secret was derived.',
      );
    }
    final framed = _parse(message);
    if (framed.conversationId != conversationId) {
      throw const PqForgeException('Conversation id does not match');
    }
    if (framed.ratchet != ratchet) {
      throw const PqForgeException('Conversation ratchet does not match');
    }
    final initial = PqxdhMessage.parse(framed.payload, kem: level.kem);
    final handshake = await Pqxdh.accept(
      identityKey: identityKey,
      signedPrekey: signedPrekey,
      kemSecretKey: kemSecretKey,
      oneTimePrekey: oneTimePrekey,
      initialMessage: initial,
      extraAssociatedData: _associated(
        conversationId: conversationId,
        messageId: messageId,
        ratchet: ratchet,
        level: level,
        trustPublicKey: trustPublicKey,
      ),
      suite: level.suite,
      kem: level.kem,
      offload: offload,
    );
    try {
      final session = await _afterHandshake(
        secret: handshake.sharedSecret,
        conversationId: conversationId,
        ratchet: ratchet,
        remote: null,
        local: signedPrekey,
        suite: level.suite,
        chunksPerMessage: chunksPerMessage,
        offload: offload,
      );
      return ConversationAccepted(session, handshake.plaintext);
    } finally {
      handshake.ratchet.dispose();
      secureZero(handshake.sharedSecret.bytes);
    }
  }

  /// Restores [toBytes].
  static Future<ConversationSession> fromBytes(
    Uint8List bytes, {
    bool offload = true,
  }) async {
    final reader = _Reader(bytes);
    final magic = reader.take(4);
    if (magic[0] != 0x43 ||
        magic[1] != 0x56 ||
        magic[2] != 0x53 ||
        magic[3] != 0x31 ||
        reader.u8() != 1) {
      throw const PqForgeException('Not a conversation session');
    }
    final kind = _kind(reader.u8());
    final id = utf8.decode(reader.block());
    final payload = reader.block();
    if (!reader.done) {
      throw const PqForgeException('Trailing bytes on a conversation session');
    }
    if (kind == ConversationRatchet.doubleRatchet) {
      final elliptic = DoubleRatchet.fromBytes(payload);
      return ConversationSession._(
        conversationId: id,
        ratchet: kind,
        elliptic: elliptic,
        triple: null,
        suite: elliptic.suite,
      );
    }
    final triple = await TripleRatchet.fromBytes(payload, offload: offload);
    return ConversationSession._(
      conversationId: id,
      ratchet: kind,
      elliptic: null,
      triple: triple,
      suite: triple.suite,
    );
  }

  final String conversationId;
  final ConversationRatchet ratchet;
  final PqForgeCipherSuite suite;
  final DoubleRatchet? _elliptic;
  final TripleRatchet? _triple;
  bool _dead = false;

  /// One ratchet message, framed as `CV01`.
  Future<Uint8List> seal(
    Uint8List plaintext, {
    required String messageId,
  }) async {
    _live();
    _requireText(messageId, 'messageId');
    final aad = _messageAad(conversationId, messageId);
    final payload = _elliptic != null
        ? _elliptic.seal(plaintext, aad: aad).bytes
        : (await _triple!.seal(plaintext, aad: aad)).bytes;
    return _frame(ratchet, conversationId, payload);
  }

  /// Opens a `CV01` message.
  Future<Uint8List> open(Uint8List message, {required String messageId}) async {
    _live();
    _requireText(messageId, 'messageId');
    final framed = _parse(message);
    if (framed.conversationId != conversationId || framed.ratchet != ratchet) {
      throw const PqForgeException('Conversation message does not match');
    }
    final aad = _messageAad(conversationId, messageId);
    if (_elliptic != null) {
      return _elliptic.open(
        DoubleRatchetMessage.parse(framed.payload),
        aad: aad,
      );
    }
    return _triple!.open(TripleRatchetMessage.parse(framed.payload), aad: aad);
  }

  /// Session record. A Triple Ratchet record does not contain the expanded
  /// decapsulation key.
  Uint8List toBytes() {
    _live();
    final inner = _elliptic != null ? _elliptic.toBytes() : _triple!.toBytes();
    final id = Uint8List.fromList(utf8.encode(conversationId));
    final builder = BytesBuilder();
    builder.add(const [0x43, 0x56, 0x53, 0x31]);
    builder.addByte(1);
    builder.addByte(ratchet == ConversationRatchet.doubleRatchet ? 1 : 2);
    builder.add(_u32(id.length));
    builder.add(id);
    builder.add(_u32(inner.length));
    builder.add(inner);
    return builder.takeBytes();
  }

  void wipe() {
    if (_dead) return;
    _dead = true;
    _elliptic?.dispose();
    _triple?.wipe();
  }

  void _live() {
    if (_dead) throw StateError('ConversationSession has been wiped');
  }
}

final class _Framed {
  _Framed(this.ratchet, this.conversationId, this.payload);

  final ConversationRatchet ratchet;
  final String conversationId;
  final Uint8List payload;
}

Future<ConversationSession> _afterHandshake({
  required SharedSecret32 secret,
  required String conversationId,
  required ConversationRatchet ratchet,
  required RatchetPublicKey? remote,
  required RatchetKeyPair? local,
  required PqForgeCipherSuite suite,
  required int chunksPerMessage,
  required bool offload,
}) async {
  if (ratchet == ConversationRatchet.doubleRatchet) {
    final elliptic = remote != null
        ? await DoubleRatchet.initiate(
            sharedSecret: secret,
            remoteRatchetKey: remote,
            suite: suite,
            encryptHeaders: true,
          )
        : DoubleRatchet.accept(
            sharedSecret: secret,
            ratchetKey: local!,
            suite: suite,
            encryptHeaders: true,
          );
    return ConversationSession._(
      conversationId: conversationId,
      ratchet: ratchet,
      elliptic: elliptic,
      triple: null,
      suite: suite,
    );
  }
  final triple = remote != null
      ? await TripleRatchet.initiate(
          sharedSecret: secret,
          remoteRatchetKey: remote,
          suite: suite,
          encryptHeaders: true,
          chunksPerMessage: chunksPerMessage,
          offload: offload,
        )
      : TripleRatchet.accept(
          sharedSecret: secret,
          ratchetKey: local!,
          suite: suite,
          encryptHeaders: true,
          chunksPerMessage: chunksPerMessage,
          offload: offload,
        );
  return ConversationSession._(
    conversationId: conversationId,
    ratchet: ratchet,
    elliptic: null,
    triple: triple,
    suite: suite,
  );
}

Future<void> _requirePinned(
  PqxdhBundle bundle,
  ConversationLevel level,
  Uint8List pin, {
  required bool offload,
}) async {
  if (!bundle.identifiesPrekeys) {
    throw const PqForgeException(
      'Conversation bundle has no prekey ids. No secret was derived.',
    );
  }
  if (bundle.kem != level.kem) {
    throw const PqForgeException(
      'Conversation KEM does not match. No secret was derived.',
    );
  }
  if (bundle.trust != level.trust) {
    throw const PqForgeException(
      'Conversation identity algorithm does not match. No secret was derived.',
    );
  }
  final key = bundle.trustPublicKey;
  if (key == null ||
      key.length != pin.length ||
      !key.rangeEquals(0, key.length, pin)) {
    throw const PqForgeException(
      'Conversation identity does not match the pinned key. No secret was derived.',
    );
  }
  if (!await Pqxdh.trustAuthentic(bundle, offload: offload)) {
    throw const PqForgeException(
      'Conversation bundle signature is not valid. No secret was derived.',
    );
  }
}

void _requireText(String value, String name) {
  if (value.isEmpty || utf8.encode(value).length > 1024) {
    throw ArgumentError.value(value, name, '1 to 1024 bytes');
  }
}

Uint8List _associated({
  required String conversationId,
  required String messageId,
  required ConversationRatchet ratchet,
  required ConversationLevel level,
  required Uint8List trustPublicKey,
}) {
  final kind = ratchet == ConversationRatchet.doubleRatchet ? '1' : '2';
  final prefix = utf8.encode(
    'pqforge/conversation/v2\n$conversationId\n$messageId\n$kind\n'
    '${level.kem.algorithm.name}\n${level.trust.id}\n${level.suite.id}\n',
  );
  final out = Uint8List(prefix.length + trustPublicKey.length);
  out.setRange(0, prefix.length, prefix);
  out.setRange(prefix.length, out.length, trustPublicKey);
  return out;
}

Uint8List _messageAad(String conversationId, String messageId) =>
    Uint8List.fromList(
      utf8.encode('pqforge/conversation/v2\n$conversationId\n$messageId'),
    );

Uint8List _frame(
  ConversationRatchet ratchet,
  String conversationId,
  Uint8List payload,
) {
  final id = Uint8List.fromList(utf8.encode(conversationId));
  final out = Uint8List(4 + 1 + 1 + 2 + id.length + payload.length);
  out[0] = 0x43;
  out[1] = 0x56;
  out[2] = 0x30;
  out[3] = 0x31;
  out[4] = 1;
  out[5] = ratchet == ConversationRatchet.doubleRatchet ? 1 : 2;
  ByteData.sublistView(out).setUint16(6, id.length);
  out.setRange(8, 8 + id.length, id);
  out.setRange(8 + id.length, out.length, payload);
  return out;
}

_Framed _parse(Uint8List bytes) {
  if (bytes.length < 8 ||
      bytes[0] != 0x43 ||
      bytes[1] != 0x56 ||
      bytes[2] != 0x30 ||
      bytes[3] != 0x31 ||
      bytes[4] != 1) {
    throw const PqForgeException('Not a conversation message');
  }
  final idLength = ByteData.sublistView(bytes, 6, 8).getUint16(0);
  if (bytes.length < 8 + idLength) {
    throw const PqForgeException('Conversation message is truncated');
  }
  return _Framed(
    _kind(bytes[5]),
    utf8.decode(Uint8List.sublistView(bytes, 8, 8 + idLength)),
    Uint8List.sublistView(bytes, 8 + idLength),
  );
}

ConversationRatchet _kind(int byte) => switch (byte) {
  1 => ConversationRatchet.doubleRatchet,
  2 => ConversationRatchet.tripleRatchet,
  _ => throw const PqForgeException('Unknown conversation ratchet'),
};

Uint8List _u32(int value) {
  final bytes = Uint8List(4);
  ByteData.sublistView(bytes).setUint32(0, value);
  return bytes;
}

final class _Reader {
  _Reader(this.bytes);

  final Uint8List bytes;
  int _offset = 0;

  bool get done => _offset == bytes.length;

  Uint8List take(int length) {
    if (_offset + length > bytes.length) {
      throw const PqForgeException('Truncated conversation session');
    }
    final out = Uint8List.fromList(
      Uint8List.sublistView(bytes, _offset, _offset + length),
    );
    _offset += length;
    return out;
  }

  int u8() => take(1)[0];

  Uint8List block() {
    final length = ByteData.sublistView(take(4)).getUint32(0);
    return take(length);
  }
}
