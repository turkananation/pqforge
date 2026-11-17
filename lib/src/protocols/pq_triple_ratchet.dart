/// Triple Ratchet: Double Ratchet beside the ML-KEM Braid.
///
/// Signal Double Ratchet revision 4, sections 5 and 6. The sparse ratchet's
/// SCKA is [MlKemBraid]. Message keys from both ratchets go through
/// [SpqrKdf.hybrid]. One AEAD, under that key. Not two encryptions.
/// Not X-Wing. Not libsignal bytes. Not a FIPS handshake. `PqFipsMode`
/// only refuses ChaCha20-Poly1305. The session is not serialized: the braid
/// holds an expanded ML-KEM decapsulation key until the epoch finishes.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:zeroize/zeroize.dart';

import '../algorithms/pq_fips.dart';
import '../cipher/pq_cipher_suite.dart';
import '../exceptions/pqforge_exception.dart';
import '../primitives/pq_primitives.dart';
import 'pq_braid_erasure.dart';
import 'pq_double_ratchet.dart';
import 'pq_mlkem_braid.dart';
import 'pq_ratchet_types.dart';
import 'pq_spqr_kdf.dart';

/// The braid's KEM. Not X-Wing.
enum SpqrKem {
  /// ML-KEM-768, split into Encaps1 and Encaps2. Not a one-shot encapsulate.
  mlKem768,
}

/// `TR01` message. The Double Ratchet header is inside it, unchanged.
///
/// `magic || version || dh || pn || n || pqN || braid || ciphertext || tag`.
/// The braid encoding is [BraidMessage.encode]. The nonce is 12 zero bytes
/// and is not on the wire. The message key is used once.
final class TripleRatchetMessage {
  TripleRatchetMessage._(this.bytes, this.headerLength);

  factory TripleRatchetMessage.parse(Uint8List bytes) {
    if (bytes.length < _fixedHeader + _braidBare + 16) {
      throw const PqForgeException('Triple Ratchet message is truncated');
    }
    for (var i = 0; i < 4; i++) {
      if (bytes[i] != _magic[i]) {
        throw const PqForgeException('Not a Triple Ratchet message');
      }
    }
    if (bytes[4] != 1) {
      throw const PqForgeException('Unknown Triple Ratchet version');
    }
    final type = BraidMessageType.byWire(bytes[_fixedHeader + 8]);
    final braidLength = type.carriesChunk
        ? _braidBare + 2 + BraidErasure.chunkBytes
        : _braidBare;
    final headerLength = _fixedHeader + braidLength;
    if (bytes.length < headerLength + 16) {
      throw const PqForgeException('Triple Ratchet message is truncated');
    }
    return TripleRatchetMessage._(bytes, headerLength);
  }

  static const _magic = <int>[0x54, 0x52, 0x30, 0x31];

  final Uint8List bytes;
  final int headerLength;

  Uint8List get header => Uint8List.sublistView(bytes, 0, headerLength);

  Uint8List get ciphertext => Uint8List.sublistView(bytes, headerLength);

  Uint8List get dh => Uint8List.sublistView(bytes, 5, 37);

  int get pn => ByteData.sublistView(bytes, 37, 41).getUint32(0);

  int get n => ByteData.sublistView(bytes, 41, 45).getUint32(0);

  int get postQuantumN => ByteData.sublistView(bytes, 45, 49).getUint32(0);

  BraidMessage get braid => BraidMessage.parse(
    Uint8List.sublistView(bytes, _fixedHeader, headerLength),
  );
}

/// Hybrid session. [initiate] is Alice. [accept] is Bob.
final class TripleRatchet {
  TripleRatchet._(this._elliptic, this._sparse, this.suite);

  /// Alice. [sharedSecret] is split into an X25519 seed and a braid seed.
  static Future<TripleRatchet> initiate({
    required SharedSecret32 sharedSecret,
    required RatchetPublicKey remoteRatchetKey,
    SpqrKem kem = SpqrKem.mlKem768,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
    int maxSkip = DoubleRatchet.defaultMaxSkip,
    RatchetKeyPair? ratchetKey,
    Uint8List Function(int length)? randomBytes,
    Future<RatchetKeyPair> Function(int step)? ratchetKeys,
  }) async {
    _require(kem, suite, maxSkip);
    final parts = SpqrKdf.split(sharedSecret.bytes);
    try {
      final elliptic = await DoubleRatchet.initiate(
        sharedSecret: SharedSecret32(parts.elliptic),
        remoteRatchetKey: remoteRatchetKey,
        suite: suite,
        info: ellipticInfo,
        maxSkip: maxSkip,
        ratchetKey: ratchetKey,
        ratchetKeys: ratchetKeys,
      );
      return TripleRatchet._(
        elliptic,
        _Sparse.alice(parts.braid, maxSkip: maxSkip, randomBytes: randomBytes),
        suite,
      );
    } finally {
      secureZero(parts.elliptic);
      secureZero(parts.braid);
    }
  }

  /// Bob. [ratchetKey] is the X25519 key Alice already used.
  static TripleRatchet accept({
    required SharedSecret32 sharedSecret,
    required RatchetKeyPair ratchetKey,
    SpqrKem kem = SpqrKem.mlKem768,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
    int maxSkip = DoubleRatchet.defaultMaxSkip,
    Uint8List Function(int length)? randomBytes,
    Future<RatchetKeyPair> Function(int step)? ratchetKeys,
  }) {
    _require(kem, suite, maxSkip);
    final parts = SpqrKdf.split(sharedSecret.bytes);
    try {
      final elliptic = DoubleRatchet.accept(
        sharedSecret: SharedSecret32(parts.elliptic),
        ratchetKey: ratchetKey,
        suite: suite,
        info: ellipticInfo,
        maxSkip: maxSkip,
        ratchetKeys: ratchetKeys,
      );
      return TripleRatchet._(
        elliptic,
        _Sparse.bob(parts.braid, maxSkip: maxSkip, randomBytes: randomBytes),
        suite,
      );
    } finally {
      secureZero(parts.elliptic);
      secureZero(parts.braid);
    }
  }

  /// HKDF info of the X25519 half. Not [DoubleRatchet.defaultInfo].
  static final Uint8List ellipticInfo = Uint8List.fromList(
    utf8.encode('pqforge-triple-ratchet-v1-ec'),
  );

  final DoubleRatchet _elliptic;
  final _Sparse _sparse;
  final PqForgeCipherSuite suite;
  bool _dead = false;

  /// One hybrid ciphertext. Advances both ratchets.
  Future<TripleRatchetMessage> seal(
    Uint8List plaintext, {
    Uint8List? aad,
  }) async {
    _live();
    final elliptic = _elliptic.takeSendingMessageKey();
    try {
      final postQuantum = await _guard(() => _sparse.send());
      final key = SpqrKdf.hybrid(
        ellipticMessageKey: elliptic.messageKey,
        postQuantumMessageKey: postQuantum.messageKey,
      );
      try {
        final braid = postQuantum.message.encode();
        final headerLength = _fixedHeader + braid.length;
        final body = _encrypt(
          key,
          plaintext,
          _aad(aad, _headerOf(elliptic, postQuantum.n, braid)),
        );
        final out = Uint8List(headerLength + body.length);
        _writeHeader(out, elliptic, postQuantum.n, braid);
        out.setRange(headerLength, out.length, body);
        return TripleRatchetMessage._(out, headerLength);
      } finally {
        secureZero(key);
        secureZero(postQuantum.messageKey);
      }
    } finally {
      secureZero(elliptic.messageKey);
    }
  }

  /// Opens one message. A bad braid MAC closes the session.
  Future<Uint8List> open(TripleRatchetMessage message, {Uint8List? aad}) async {
    _live();
    final elliptic = await _elliptic.takeReceivingMessageKey(
      dh: message.dh,
      pn: message.pn,
      n: message.n,
    );
    try {
      final postQuantum = await _guard(
        () => _sparse.receive(message.braid, message.postQuantumN),
      );
      final key = SpqrKdf.hybrid(
        ellipticMessageKey: elliptic,
        postQuantumMessageKey: postQuantum,
      );
      try {
        return _decrypt(key, message, aad);
      } finally {
        secureZero(key);
        secureZero(postQuantum);
      }
    } finally {
      secureZero(elliptic);
    }
  }

  /// Zeros both ratchets, including a live decapsulation key.
  void wipe() {
    if (_dead) return;
    _dead = true;
    _elliptic.dispose();
    _sparse.wipe();
  }

  Future<T> _guard<T>(Future<T> Function() body) async {
    try {
      return await body();
    } catch (error) {
      if (_sparse.isClosed) wipe();
      rethrow;
    }
  }

  void _live() {
    if (_dead) throw StateError('TripleRatchet has been wiped');
  }

  Uint8List _encrypt(Uint8List key, Uint8List plaintext, Uint8List aad) =>
      switch (suite) {
        PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmEncrypt(
          key: key,
          nonce: _zeroNonce,
          plaintext: plaintext,
          aad: aad,
        ),
        PqForgeCipherSuite.chaCha20Poly1305 =>
          PqSymmetricPrimitives.chacha20Poly1305Encrypt(
            key: key,
            nonce: _zeroNonce,
            plaintext: plaintext,
            aad: aad,
          ),
      };

  Uint8List _decrypt(
    Uint8List key,
    TripleRatchetMessage message,
    Uint8List? aad,
  ) => switch (suite) {
    PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmDecrypt(
      key: key,
      nonce: _zeroNonce,
      ciphertext: message.ciphertext,
      aad: _aad(aad, message.header),
    ),
    PqForgeCipherSuite.chaCha20Poly1305 =>
      PqSymmetricPrimitives.chacha20Poly1305Decrypt(
        key: key,
        nonce: _zeroNonce,
        ciphertext: message.ciphertext,
        aad: _aad(aad, message.header),
      ),
  };

  static void _require(SpqrKem kem, PqForgeCipherSuite suite, int maxSkip) {
    if (kem != SpqrKem.mlKem768) {
      throw ArgumentError.value(kem, 'kem', 'the braid is ML-KEM-768');
    }
    if (maxSkip < 0) {
      throw ArgumentError.value(maxSkip, 'maxSkip', 'must be non-negative');
    }
    PqFipsMode.requireApprovedSuite(suite);
  }
}

const _fixedHeader = 49;
const _braidBare = 9;
final Uint8List _zeroNonce = Uint8List(12);

Uint8List _headerOf(
  ({Uint8List messageKey, int pn, int n, RatchetPublicKey dh}) elliptic,
  int postQuantumN,
  Uint8List braid,
) {
  final out = Uint8List(_fixedHeader + braid.length);
  _writeHeader(out, elliptic, postQuantumN, braid);
  return out;
}

void _writeHeader(
  Uint8List out,
  ({Uint8List messageKey, int pn, int n, RatchetPublicKey dh}) elliptic,
  int postQuantumN,
  Uint8List braid,
) {
  out[0] = 0x54;
  out[1] = 0x52;
  out[2] = 0x30;
  out[3] = 0x31;
  out[4] = 1;
  out.setRange(5, 37, elliptic.dh.bytes);
  final data = ByteData.sublistView(out);
  data.setUint32(37, elliptic.pn);
  data.setUint32(41, elliptic.n);
  data.setUint32(45, postQuantumN);
  out.setRange(_fixedHeader, _fixedHeader + braid.length, braid);
}

Uint8List _aad(Uint8List? aad, Uint8List header) {
  if (aad == null || aad.isEmpty) return header;
  final out = Uint8List(aad.length + header.length);
  out.setRange(0, aad.length, aad);
  out.setRange(aad.length, out.length, header);
  return out;
}

final class _Chain {
  _Chain(this.key);

  Uint8List key;
  int n = 0;

  void wipe() => secureZero(key);
}

final class _EpochChains {
  _EpochChains({this.send, this.receive});

  _Chain? send;
  _Chain? receive;

  void wipe() {
    send?.wipe();
    receive?.wipe();
  }
}

/// Section 5, with the braid as the SCKA. Message numbers start at 1.
final class _Sparse {
  _Sparse._({
    required this._braid,
    required this._root,
    required _Chain send,
    required _Chain receive,
    required this._bob,
    required this._maxSkip,
  }) : _epoch = 0 {
    _chains[0] = _EpochChains(send: send, receive: receive);
  }

  factory _Sparse.alice(
    Uint8List sharedSecret, {
    required int maxSkip,
    Uint8List Function(int length)? randomBytes,
  }) {
    final start = SpqrKdf.chainStart(sharedSecret);
    final session = _Sparse._(
      braid: MlKemBraid.alice(sharedSecret, randomBytes: randomBytes),
      root: start.root,
      send: _Chain(start.sender),
      receive: _Chain(start.receiver),
      bob: false,
      maxSkip: maxSkip,
    );
    return session;
  }

  factory _Sparse.bob(
    Uint8List sharedSecret, {
    required int maxSkip,
    Uint8List Function(int length)? randomBytes,
  }) {
    final start = SpqrKdf.chainStart(sharedSecret);
    return _Sparse._(
      braid: MlKemBraid.bob(sharedSecret, randomBytes: randomBytes),
      root: start.root,
      send: _Chain(start.receiver),
      receive: _Chain(start.sender),
      bob: true,
      maxSkip: maxSkip,
    );
  }

  final MlKemBraid _braid;
  final bool _bob;
  final int _maxSkip;
  final Map<int, _EpochChains> _chains = {};
  final Map<int, Map<int, Uint8List>> _skipped = {};
  Uint8List _root;
  int _epoch;

  bool get isClosed => _braid.isClosed;

  Future<({BraidMessage message, int n, Uint8List messageKey})> send() async {
    final sent = await _braid.send();
    if (sent.output != null) {
      _mix(sent.output!);
      _clearOld(sent.sendingEpoch);
    }
    final previous = _chains[sent.sendingEpoch - 1];
    if (previous?.send != null) {
      previous!.send!.wipe();
      previous.send = null;
    }
    final chain = _chains[sent.sendingEpoch]?.send;
    if (chain == null) {
      throw const PqForgeException('Sending chain is not initialized');
    }
    final messageKey = _ratchet(chain);
    return (message: sent.message, n: chain.n, messageKey: messageKey);
  }

  Future<Uint8List> receive(BraidMessage message, int n) async {
    if (n < 1 || n > 0xFFFFFFFF) {
      throw const PqForgeException(
        'Sparse Post-Quantum Ratchet message number is invalid',
      );
    }
    final got = await _braid.receive(message);
    if (got.output != null) _mix(got.output!);
    final cached = _skipped[got.receivingEpoch]?.remove(n);
    if (cached != null) {
      if (_skipped[got.receivingEpoch]!.isEmpty) {
        _skipped.remove(got.receivingEpoch);
      }
      return cached;
    }
    final chain = _chains[got.receivingEpoch]?.receive;
    if (chain == null) {
      throw const PqForgeException('Receiving chain is not initialized');
    }
    if (chain.n + _maxSkip < n) {
      throw const PqForgeException(
        'Sparse Post-Quantum Ratchet header skips more messages than maxSkip',
      );
    }
    while (chain.n + 1 < n) {
      final skipped = _ratchet(chain);
      (_skipped[got.receivingEpoch] ??= {})[chain.n] = skipped;
    }
    return _ratchet(chain);
  }

  void wipe() {
    secureZero(_root);
    for (final chains in _chains.values) {
      chains.wipe();
    }
    _chains.clear();
    for (final keys in _skipped.values) {
      for (final key in keys.values) {
        secureZero(key);
      }
    }
    _skipped.clear();
    _braid.wipe();
  }

  void _mix(BraidOutput output) {
    if (output.epoch != _epoch + 1) {
      secureZero(output.key);
      throw const PqForgeException('The braid epoch skipped ahead');
    }
    final next = SpqrKdf.addEpoch(root: _root, sckaOutput: output.key);
    secureZero(output.key);
    secureZero(_root);
    _root = next.root;
    final send = _bob ? next.receiver : next.sender;
    final receive = _bob ? next.sender : next.receiver;
    _chains[output.epoch] = _EpochChains(
      send: _Chain(send),
      receive: _Chain(receive),
    );
    _epoch = output.epoch;
  }

  void _clearOld(int sendingEpoch) {
    final dropped = _chains.remove(sendingEpoch - 2);
    dropped?.wipe();
    final skipped = _skipped.remove(sendingEpoch - 2);
    if (skipped == null) return;
    for (final key in skipped.values) {
      secureZero(key);
    }
  }

  Uint8List _ratchet(_Chain chain) {
    if (chain.n == 0xFFFFFFFF) {
      throw const PqForgeException(
        'Sparse Post-Quantum chain counter exhausted',
      );
    }
    chain.n += 1;
    final step = SpqrKdf.chainKey(chain.key, counter: chain.n);
    chain.key.setRange(0, 32, step.chain);
    secureZero(step.chain);
    return step.message;
  }
}
