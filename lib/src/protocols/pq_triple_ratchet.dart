/// Triple Ratchet: Double Ratchet beside the ML-KEM Braid.
///
/// Signal Double Ratchet revision 4, sections 5 and 6. The sparse ratchet's
/// SCKA is [MlKemBraid]. Message keys from both ratchets go through
/// [SpqrKdf.hybrid]. One AEAD, under that key. Not two encryptions.
/// Not X-Wing. Not libsignal bytes. Not a FIPS handshake. `PqFipsMode`
/// only refuses ChaCha20-Poly1305. [toBytes] stores the braid seed, not
/// the expanded decapsulation key. Header encryption is opt-in and uses
/// `TRH1`. A clear header stays `TR01`.
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

/// `TR01` message, or `TRH1` when the header is encrypted.
///
/// Clear layout, version 1:
/// `magic || version || dh || pn || n || pqN || braid || ciphertext || tag`.
/// Version 2 inserts `count` (uint16) and that many braid messages.
///
/// `TRH1` is `magic || version || nonce(12) || length || AEAD(clear header)
/// || body`. The nonce is 12 random bytes. A header key lasts one sending
/// chain. The body nonce is still 12 zero bytes.
final class TripleRatchetMessage {
  TripleRatchetMessage._(
    this.bytes, {
    required this.headerLength,
    required this.headerEncrypted,
    required this.clearHeaderLength,
  });

  factory TripleRatchetMessage.parse(Uint8List bytes) {
    if (bytes.length >= 4 &&
        bytes[0] == 0x54 &&
        bytes[1] == 0x52 &&
        bytes[2] == 0x48 &&
        bytes[3] == 0x31) {
      if (bytes.length < 21 || bytes[4] != 1) {
        throw const PqForgeException('Triple Ratchet message is truncated');
      }
      final length = ByteData.sublistView(bytes, 17, 21).getUint32(0);
      if (bytes.length < 21 + length + 16) {
        throw const PqForgeException('Triple Ratchet message is truncated');
      }
      return TripleRatchetMessage._(
        bytes,
        headerLength: 21 + length,
        headerEncrypted: true,
        clearHeaderLength: 0,
      );
    }
    return _parseClear(bytes);
  }

  static TripleRatchetMessage _parseClear(Uint8List bytes) {
    if (bytes.length < _fixedHeader + _braidBare + 16) {
      throw const PqForgeException('Triple Ratchet message is truncated');
    }
    for (var i = 0; i < 4; i++) {
      if (bytes[i] != _magic[i]) {
        throw const PqForgeException('Not a Triple Ratchet message');
      }
    }
    final version = bytes[4];
    if (version != 1 && version != 2) {
      throw const PqForgeException('Unknown Triple Ratchet version');
    }
    final braids = _readBraids(bytes, version);
    var offset = version == 1 ? _fixedHeader : _fixedHeader + 2;
    for (final braid in braids) {
      offset += braid.encode().length;
    }
    if (bytes.length < offset + 16) {
      throw const PqForgeException('Triple Ratchet message is truncated');
    }
    return TripleRatchetMessage._(
      bytes,
      headerLength: offset,
      headerEncrypted: false,
      clearHeaderLength: offset,
    );
  }

  static const _magic = <int>[0x54, 0x52, 0x30, 0x31];

  final Uint8List bytes;
  final int headerLength;
  final bool headerEncrypted;
  final int clearHeaderLength;

  Uint8List get header => Uint8List.sublistView(bytes, 0, headerLength);

  Uint8List get ciphertext => Uint8List.sublistView(bytes, headerLength);

  Uint8List get headerNonce =>
      headerEncrypted ? Uint8List.sublistView(bytes, 5, 17) : Uint8List(0);

  Uint8List get encryptedHeader => headerEncrypted
      ? Uint8List.sublistView(bytes, 21, headerLength)
      : Uint8List(0);

  Uint8List get _clear => headerEncrypted
      ? (throw StateError('Triple Ratchet header is encrypted'))
      : bytes;

  Uint8List get dh => Uint8List.sublistView(_clear, 5, 37);

  int get pn => ByteData.sublistView(_clear, 37, 41).getUint32(0);

  int get n => ByteData.sublistView(_clear, 41, 45).getUint32(0);

  int get postQuantumN => ByteData.sublistView(_clear, 45, 49).getUint32(0);

  BraidMessage get braid => braids.first;

  List<BraidMessage> get braids {
    if (headerEncrypted) {
      throw StateError('Triple Ratchet header is encrypted');
    }
    return _readBraids(bytes, bytes[4]);
  }
}

/// Hybrid session. [initiate] is Alice. [accept] is Bob.
final class TripleRatchet {
  TripleRatchet._(
    this._elliptic,
    this._sparse,
    this.suite,
    this.chunksPerMessage,
  );

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
    bool encryptHeaders = false,
    int chunksPerMessage = 1,
    bool offload = true,
  }) async {
    _require(kem, suite, maxSkip, chunksPerMessage);
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
        encryptHeaders: encryptHeaders,
      );
      return TripleRatchet._(
        elliptic,
        _Sparse.alice(
          parts.braid,
          maxSkip: maxSkip,
          randomBytes: randomBytes,
          offload: offload,
        ),
        suite,
        chunksPerMessage,
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
    bool encryptHeaders = false,
    int chunksPerMessage = 1,
    bool offload = true,
  }) {
    _require(kem, suite, maxSkip, chunksPerMessage);
    final parts = SpqrKdf.split(sharedSecret.bytes);
    try {
      final elliptic = DoubleRatchet.accept(
        sharedSecret: SharedSecret32(parts.elliptic),
        ratchetKey: ratchetKey,
        suite: suite,
        info: ellipticInfo,
        maxSkip: maxSkip,
        ratchetKeys: ratchetKeys,
        encryptHeaders: encryptHeaders,
      );
      return TripleRatchet._(
        elliptic,
        _Sparse.bob(
          parts.braid,
          maxSkip: maxSkip,
          randomBytes: randomBytes,
          offload: offload,
        ),
        suite,
        chunksPerMessage,
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
  final int chunksPerMessage;
  bool _dead = false;

  /// One hybrid ciphertext. Advances both ratchets.
  Future<TripleRatchetMessage> seal(
    Uint8List plaintext, {
    Uint8List? aad,
  }) async {
    _live();
    final elliptic = _elliptic.takeSendingMessageKey();
    try {
      final postQuantum = await _guard(
        () => _sparse.send(chunks: chunksPerMessage),
      );
      final key = SpqrKdf.hybrid(
        ellipticMessageKey: elliptic.messageKey,
        postQuantumMessageKey: postQuantum.messageKey,
      );
      try {
        final clear = _clearHeader(
          elliptic,
          postQuantum.n,
          postQuantum.messages,
        );
        if (!_elliptic.encryptHeaders) {
          final body = _encrypt(key, plaintext, _aad(aad, clear));
          final out = Uint8List(clear.length + body.length);
          out.setRange(0, clear.length, clear);
          out.setRange(clear.length, out.length, body);
          return TripleRatchetMessage.parse(out);
        }
        final sealed = _elliptic.encryptSendingHeader(clear);
        try {
          final body = _encrypt(key, plaintext, _aad(aad, sealed.encrypted));
          return TripleRatchetMessage.parse(
            _packEncrypted(sealed.nonce, sealed.encrypted, body),
          );
        } finally {
          secureZero(sealed.encrypted);
        }
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
    if (message.headerEncrypted != _elliptic.encryptHeaders) {
      throw const PqForgeException(
        'Triple Ratchet header encryption does not match the session',
      );
    }
    if (!message.headerEncrypted) {
      final elliptic = await _elliptic.takeReceivingMessageKey(
        dh: message.dh,
        pn: message.pn,
        n: message.n,
      );
      try {
        return await _openClear(message, elliptic, aad);
      } finally {
        secureZero(elliptic);
      }
    }
    final opened = await _elliptic.openExternalHeader(
      nonce: message.headerNonce,
      encrypted: message.encryptedHeader,
      read: (clear) {
        if (clear.length < _fixedHeader) {
          throw const PqForgeException('Triple Ratchet header is truncated');
        }
        return (
          dh: Uint8List.fromList(Uint8List.sublistView(clear, 5, 37)),
          pn: ByteData.sublistView(clear, 37, 41).getUint32(0),
          n: ByteData.sublistView(clear, 41, 45).getUint32(0),
        );
      },
    );
    try {
      final full = Uint8List(
        opened.clearHeader.length + message.ciphertext.length,
      );
      full.setRange(0, opened.clearHeader.length, opened.clearHeader);
      full.setRange(opened.clearHeader.length, full.length, message.ciphertext);
      final clear = TripleRatchetMessage.parse(full);
      final postQuantum = await _guard(
        () => _sparse.receiveAll(clear.braids, clear.postQuantumN),
      );
      final key = SpqrKdf.hybrid(
        ellipticMessageKey: opened.messageKey,
        postQuantumMessageKey: postQuantum,
      );
      try {
        return _decryptRaw(
          key,
          message.ciphertext,
          _aad(aad, message.encryptedHeader),
        );
      } finally {
        secureZero(key);
        secureZero(postQuantum);
      }
    } finally {
      secureZero(opened.messageKey);
      secureZero(opened.clearHeader);
    }
  }

  /// Zeros both ratchets, including a live decapsulation key.
  void wipe() {
    if (_dead) return;
    _dead = true;
    _elliptic.dispose();
    _sparse.wipe();
  }

  /// Session record. The expanded ML-KEM decapsulation key is not in it.
  /// A live braid epoch is the 64-byte seed, re-expanded by [fromBytes].
  Uint8List toBytes() {
    _live();
    final elliptic = _elliptic.toBytes();
    final sparse = _sparse.exportState();
    final braid = _sparse.braidBytes();
    final builder = BytesBuilder();
    builder.add(const [0x54, 0x52, 0x53, 0x31]);
    builder.addByte(1);
    builder.addByte(chunksPerMessage);
    _addBlock(builder, elliptic);
    _addBlock(builder, sparse);
    _addBlock(builder, braid);
    return builder.takeBytes();
  }

  /// Restores [toBytes].
  static Future<TripleRatchet> fromBytes(
    Uint8List bytes, {
    bool offload = true,
  }) async {
    final reader = _BlockReader(bytes);
    final magic = reader.take(4);
    if (magic[0] != 0x54 ||
        magic[1] != 0x52 ||
        magic[2] != 0x53 ||
        magic[3] != 0x31 ||
        reader.u8() != 1) {
      throw const PqForgeException('Not a Triple Ratchet session');
    }
    final chunks = reader.u8();
    final elliptic = DoubleRatchet.fromBytes(reader.block());
    final sparseBytes = reader.block();
    final braid = await MlKemBraid.fromBytes(reader.block(), offload: offload);
    if (!reader.done) {
      elliptic.dispose();
      braid.wipe();
      throw const PqForgeException(
        'Trailing bytes on a Triple Ratchet session',
      );
    }
    return TripleRatchet._(
      elliptic,
      _Sparse.restore(sparseBytes, braid),
      elliptic.suite,
      chunks,
    );
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

  Future<Uint8List> _openClear(
    TripleRatchetMessage message,
    Uint8List elliptic,
    Uint8List? aad,
  ) async {
    final postQuantum = await _guard(
      () => _sparse.receiveAll(message.braids, message.postQuantumN),
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
  }

  Uint8List _decryptRaw(Uint8List key, Uint8List ciphertext, Uint8List aad) =>
      switch (suite) {
        PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmDecrypt(
          key: key,
          nonce: _zeroNonce,
          ciphertext: ciphertext,
          aad: aad,
        ),
        PqForgeCipherSuite.chaCha20Poly1305 =>
          PqSymmetricPrimitives.chacha20Poly1305Decrypt(
            key: key,
            nonce: _zeroNonce,
            ciphertext: ciphertext,
            aad: aad,
          ),
      };

  static void _require(
    SpqrKem kem,
    PqForgeCipherSuite suite,
    int maxSkip,
    int chunksPerMessage,
  ) {
    if (kem != SpqrKem.mlKem768) {
      throw ArgumentError.value(kem, 'kem', 'the braid is ML-KEM-768');
    }
    if (maxSkip < 0) {
      throw ArgumentError.value(maxSkip, 'maxSkip', 'must be non-negative');
    }
    if (chunksPerMessage < 1 || chunksPerMessage > 64) {
      throw ArgumentError.value(
        chunksPerMessage,
        'chunksPerMessage',
        '1 to 64',
      );
    }
    PqFipsMode.requireApprovedSuite(suite);
  }
}

const _fixedHeader = 49;
const _braidBare = 9;
final Uint8List _zeroNonce = Uint8List(12);

Uint8List _clearHeader(
  ({Uint8List messageKey, int pn, int n, RatchetPublicKey dh}) elliptic,
  int postQuantumN,
  List<BraidMessage> messages,
) {
  final encoded = [for (final message in messages) message.encode()];
  final braidBytes = encoded.fold<int>(0, (sum, bytes) => sum + bytes.length);
  final version2 = messages.length != 1;
  final headerLength = _fixedHeader + (version2 ? 2 : 0) + braidBytes;
  final out = Uint8List(headerLength);
  out[0] = 0x54;
  out[1] = 0x52;
  out[2] = 0x30;
  out[3] = 0x31;
  out[4] = version2 ? 2 : 1;
  out.setRange(5, 37, elliptic.dh.bytes);
  final data = ByteData.sublistView(out);
  data.setUint32(37, elliptic.pn);
  data.setUint32(41, elliptic.n);
  data.setUint32(45, postQuantumN);
  var offset = _fixedHeader;
  if (version2) {
    data.setUint16(offset, messages.length);
    offset += 2;
  }
  for (final bytes in encoded) {
    out.setRange(offset, offset + bytes.length, bytes);
    offset += bytes.length;
  }
  return out;
}

Uint8List _packEncrypted(Uint8List nonce, Uint8List encrypted, Uint8List body) {
  final out = Uint8List(21 + encrypted.length + body.length);
  out[0] = 0x54;
  out[1] = 0x52;
  out[2] = 0x48;
  out[3] = 0x31;
  out[4] = 1;
  out.setRange(5, 17, nonce);
  ByteData.sublistView(out).setUint32(17, encrypted.length);
  out.setRange(21, 21 + encrypted.length, encrypted);
  out.setRange(21 + encrypted.length, out.length, body);
  return out;
}

List<BraidMessage> _readBraids(Uint8List bytes, int version) {
  if (version == 1) {
    final type = BraidMessageType.byWire(bytes[_fixedHeader + 8]);
    final length = type.carriesChunk
        ? _braidBare + 2 + BraidErasure.chunkBytes
        : _braidBare;
    return [
      BraidMessage.parse(
        Uint8List.sublistView(bytes, _fixedHeader, _fixedHeader + length),
      ),
    ];
  }
  final count = ByteData.sublistView(
    bytes,
    _fixedHeader,
    _fixedHeader + 2,
  ).getUint16(0);
  if (count < 1 || count > 64) {
    throw const PqForgeException('Triple Ratchet braid count is invalid');
  }
  final messages = <BraidMessage>[];
  var offset = _fixedHeader + 2;
  for (var i = 0; i < count; i++) {
    if (offset + _braidBare > bytes.length) {
      throw const PqForgeException('Triple Ratchet message is truncated');
    }
    final type = BraidMessageType.byWire(bytes[offset + 8]);
    final length = type.carriesChunk
        ? _braidBare + 2 + BraidErasure.chunkBytes
        : _braidBare;
    messages.add(
      BraidMessage.parse(Uint8List.sublistView(bytes, offset, offset + length)),
    );
    offset += length;
  }
  return messages;
}

Uint8List _aad(Uint8List? aad, Uint8List header) {
  if (aad == null || aad.isEmpty) return header;
  final out = Uint8List(aad.length + header.length);
  out.setRange(0, aad.length, aad);
  out.setRange(aad.length, out.length, header);
  return out;
}

void _addBlock(BytesBuilder builder, Uint8List bytes) {
  builder.add(_be32(bytes.length));
  builder.add(bytes);
}

Uint8List _be32(int value) {
  final bytes = Uint8List(4);
  ByteData.sublistView(bytes).setUint32(0, value);
  return bytes;
}

final class _BlockReader {
  _BlockReader(this.bytes);

  final Uint8List bytes;
  int _offset = 0;

  bool get done => _offset == bytes.length;

  Uint8List take(int length) {
    if (_offset + length > bytes.length) {
      throw const PqForgeException('Truncated Triple Ratchet session');
    }
    final out = Uint8List.fromList(
      Uint8List.sublistView(bytes, _offset, _offset + length),
    );
    _offset += length;
    return out;
  }

  int u8() => take(1)[0];

  int u32() => ByteData.sublistView(take(4)).getUint32(0);

  Uint8List block() => take(u32());
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
    bool offload = true,
  }) {
    final start = SpqrKdf.chainStart(sharedSecret);
    final session = _Sparse._(
      braid: MlKemBraid.alice(
        sharedSecret,
        randomBytes: randomBytes,
        offload: offload,
      ),
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
    bool offload = true,
  }) {
    final start = SpqrKdf.chainStart(sharedSecret);
    return _Sparse._(
      braid: MlKemBraid.bob(
        sharedSecret,
        randomBytes: randomBytes,
        offload: offload,
      ),
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

  Uint8List braidBytes() => _braid.toBytes();

  Uint8List exportState() {
    final builder = BytesBuilder();
    builder.addByte(_bob ? 1 : 0);
    builder.add(_be32(_maxSkip));
    builder.add(_be32(_epoch));
    builder.add(Uint8List.fromList(_root));
    builder.add(_be32(_chains.length));
    for (final entry in _chains.entries) {
      builder.add(_be32(entry.key));
      final send = entry.value.send;
      final receive = entry.value.receive;
      var flags = 0;
      if (send != null) flags |= 1;
      if (receive != null) flags |= 2;
      builder.addByte(flags);
      if (send != null) {
        builder.add(Uint8List.fromList(send.key));
        builder.add(_be32(send.n));
      }
      if (receive != null) {
        builder.add(Uint8List.fromList(receive.key));
        builder.add(_be32(receive.n));
      }
    }
    builder.add(_be32(_skipped.length));
    for (final entry in _skipped.entries) {
      builder.add(_be32(entry.key));
      builder.add(_be32(entry.value.length));
      for (final skipped in entry.value.entries) {
        builder.add(_be32(skipped.key));
        builder.add(Uint8List.fromList(skipped.value));
      }
    }
    return builder.takeBytes();
  }

  static _Sparse restore(Uint8List bytes, MlKemBraid braid) {
    final reader = _BlockReader(bytes);
    final bob = reader.u8() == 1;
    final maxSkip = reader.u32();
    final epoch = reader.u32();
    final root = reader.take(32);
    final send = _Chain(Uint8List(32));
    final receive = _Chain(Uint8List(32));
    final session = _Sparse._(
      braid: braid,
      root: root,
      send: send,
      receive: receive,
      bob: bob,
      maxSkip: maxSkip,
    );
    session._chains.clear();
    send.wipe();
    receive.wipe();
    session._epoch = epoch;
    final count = reader.u32();
    for (var i = 0; i < count; i++) {
      final id = reader.u32();
      final flags = reader.u8();
      _Chain? send;
      _Chain? receive;
      if ((flags & 1) != 0) {
        send = _Chain(reader.take(32))..n = reader.u32();
      }
      if ((flags & 2) != 0) {
        receive = _Chain(reader.take(32))..n = reader.u32();
      }
      session._chains[id] = _EpochChains(send: send, receive: receive);
    }
    final skippedEpochs = reader.u32();
    for (var i = 0; i < skippedEpochs; i++) {
      final id = reader.u32();
      final keys = reader.u32();
      final map = <int, Uint8List>{};
      for (var n = 0; n < keys; n++) {
        final number = reader.u32();
        map[number] = reader.take(32);
      }
      session._skipped[id] = map;
    }
    if (!reader.done) {
      session.wipe();
      throw const PqForgeException(
        'Trailing bytes on a sparse ratchet session',
      );
    }
    return session;
  }

  Future<({List<BraidMessage> messages, int n, Uint8List messageKey})> send({
    int chunks = 1,
  }) async {
    final sent = await _braid.send(chunks: chunks);
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
    return (messages: sent.messages, n: chain.n, messageKey: messageKey);
  }

  Future<Uint8List> receiveAll(List<BraidMessage> messages, int n) async {
    if (messages.isEmpty) {
      throw const PqForgeException('Triple Ratchet braid message is missing');
    }
    BraidReceive? last;
    for (final message in messages) {
      last = await _braid.receive(message);
      if (last.output != null) _mix(last.output!);
    }
    return _messageKey(last!.receivingEpoch, n);
  }

  Future<Uint8List> receive(BraidMessage message, int n) =>
      receiveAll([message], n);

  Future<Uint8List> _messageKey(int epoch, int n) async {
    if (n < 1 || n > 0xFFFFFFFF) {
      throw const PqForgeException(
        'Sparse Post-Quantum Ratchet message number is invalid',
      );
    }
    final cached = _skipped[epoch]?.remove(n);
    if (cached != null) {
      if (_skipped[epoch]!.isEmpty) _skipped.remove(epoch);
      return cached;
    }
    final chain = _chains[epoch]?.receive;
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
      (_skipped[epoch] ??= {})[chain.n] = skipped;
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
