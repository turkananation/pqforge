/// ML-KEM Braid, revision 1 (2025-02-21, updated 2025-09-26).
///
/// Public domain specification. This is not libsignal and not Signal
/// Messenger. The KEM is ML-KEM-768 through [MlKemIncremental]: Encaps1,
/// then Encaps2. Chunks are [BraidErasure] codewords of 32 bytes. The index
/// sits beside the chunk. A failed MAC or encapsulation-key hash closes
/// the session. The expanded decapsulation key is wiped after decapsulation
/// and is not a field this type will serialize.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart' show hmacSha256, sha3256;
import 'package:zeroize/zeroize.dart';

import '../exceptions/pqforge_exception.dart';
import 'pq_braid_erasure.dart';
import 'pq_mlkem_incremental.dart';
import 'pq_ratchet_types.dart';
import 'pq_spqr_kdf.dart';

/// Wire values from the braid specification.
enum BraidMessageType {
  none(0),
  hdr(1),
  ek(2),
  ekCt1Ack(3),
  ct1Ack(4),
  ct1(5),
  ct2(6);

  const BraidMessageType(this.wire);

  final int wire;

  static BraidMessageType byWire(int wire) => switch (wire) {
    0 => none,
    1 => hdr,
    2 => ek,
    3 => ekCt1Ack,
    4 => ct1Ack,
    5 => ct1,
    6 => ct2,
    _ => throw const PqForgeException('Unknown ML-KEM Braid message type'),
  };

  bool get carriesChunk => switch (this) {
    none || ct1Ack => false,
    _ => true,
  };
}

/// One braid message. [chunk] is 32 bytes. [index] is not inside those bytes.
final class BraidMessage {
  BraidMessage({
    required this.epoch,
    required this.type,
    int? index,
    Uint8List? chunk,
  }) : index = index,
       chunk = chunk == null ? null : Uint8List.fromList(chunk) {
    if (epoch < 0) {
      throw ArgumentError.value(epoch, 'epoch', 'negative');
    }
    final has = type.carriesChunk;
    if (has != (index != null && chunk != null)) {
      throw ArgumentError('Braid chunk presence does not match the type');
    }
    if (index != null && (index < 0 || index > 0xFFFF)) {
      throw ArgumentError.value(index, 'index', 'uint16');
    }
    if (chunk != null && chunk.length != BraidErasure.chunkBytes) {
      throw ArgumentError.value(chunk.length, 'chunk', '32 bytes');
    }
  }

  factory BraidMessage.parse(Uint8List bytes) {
    if (bytes.length < 9) {
      throw const PqForgeException('ML-KEM Braid message is truncated');
    }
    var epoch = 0;
    for (var i = 0; i < 8; i++) {
      epoch = (epoch << 8) | bytes[i];
    }
    final type = BraidMessageType.byWire(bytes[8]);
    if (!type.carriesChunk) {
      if (bytes.length != 9) {
        throw const PqForgeException('ML-KEM Braid message is truncated');
      }
      return BraidMessage(epoch: epoch, type: type);
    }
    if (bytes.length != 9 + 2 + BraidErasure.chunkBytes) {
      throw const PqForgeException('ML-KEM Braid message is truncated');
    }
    final index = (bytes[9] << 8) | bytes[10];
    return BraidMessage(
      epoch: epoch,
      type: type,
      index: index,
      chunk: Uint8List.sublistView(bytes, 11),
    );
  }

  final int epoch;
  final BraidMessageType type;
  final int? index;
  final Uint8List? chunk;

  Uint8List encode() {
    final ep = SpqrKdf.epochBytes(epoch);
    final chunkBytes = chunk;
    final length = chunkBytes == null ? 9 : 11 + chunkBytes.length;
    final out = Uint8List(length);
    out.setRange(0, 8, ep);
    out[8] = type.wire;
    final indexValue = index;
    if (chunkBytes != null && indexValue != null) {
      out[9] = indexValue >> 8;
      out[10] = indexValue & 0xff;
      out.setRange(11, out.length, chunkBytes);
    }
    return out;
  }
}

/// `KDF_OK` output for one finished epoch. The caller wipes [key].
final class BraidOutput {
  BraidOutput(this.epoch, Uint8List key) : key = Uint8List.fromList(key) {
    if (key.length != 32) {
      throw ArgumentError.value(this.key.length, 'key', '32 bytes');
    }
  }

  final int epoch;
  final Uint8List key;
}

/// What [MlKemBraid.send] returns.
final class BraidSend {
  BraidSend(BraidMessage message, this.sendingEpoch, this.output)
    : messages = [message];

  BraidSend.many(this.messages, this.sendingEpoch, this.output) {
    if (messages.isEmpty) {
      throw ArgumentError('A braid send needs a message');
    }
  }

  /// Every codeword attached to this chain step. One, unless the caller
  /// asked for more.
  final List<BraidMessage> messages;

  BraidMessage get message => messages.first;

  final int sendingEpoch;
  final BraidOutput? output;
}

/// What [MlKemBraid.receive] returns.
final class BraidReceive {
  BraidReceive(this.receivingEpoch, this.output);

  final int receivingEpoch;
  final BraidOutput? output;
}

enum _Phase {
  keysUnsampled,
  keysSampled,
  headerSent,
  ct1Received,
  ekSentCt1Received,
  noHeaderReceived,
  headerReceived,
  ct1Sampled,
  ekReceivedCt1Sampled,
  ct1Acknowledged,
  ct2Sampled,
}

/// One direction of the braid. [alice] sends the first header.
final class MlKemBraid {
  MlKemBraid._({
    required int epoch,
    required _Phase phase,
    required _Auth auth,
    required Uint8List Function(int length)? randomBytes,
    required bool offload,
    BraidDecoder? headerDecoder,
  }) : _epoch = epoch,
       _phase = phase,
       _auth = auth,
       _randomBytes = randomBytes,
       _offload = offload,
       _headerDecoder = headerDecoder;

  /// Alice, epoch 1, ready to sample a key on the first [send].
  factory MlKemBraid.alice(
    Uint8List sharedSecret, {
    Uint8List Function(int length)? randomBytes,
    bool offload = true,
  }) {
    return MlKemBraid._(
      epoch: 1,
      phase: _Phase.keysUnsampled,
      auth: _Auth.init(sharedSecret),
      randomBytes: randomBytes,
      offload: offload,
    );
  }

  /// Bob, epoch 1, waiting for Alice's header.
  factory MlKemBraid.bob(
    Uint8List sharedSecret, {
    Uint8List Function(int length)? randomBytes,
    bool offload = true,
  }) {
    return MlKemBraid._(
      epoch: 1,
      phase: _Phase.noHeaderReceived,
      auth: _Auth.init(sharedSecret),
      randomBytes: randomBytes,
      offload: offload,
      headerDecoder: BraidErasure.decoder(_headerBytes),
    );
  }

  final Uint8List Function(int length)? _randomBytes;
  final bool _offload;
  int _epoch;
  _Phase _phase;
  final _Auth _auth;
  bool _dead = false;
  bool _busy = false;

  Uint8List? _seed;
  Uint8List? _dk;
  Uint8List? _ekSeed;
  Uint8List? _ekVector;
  Uint8List? _hek;
  Uint8List? _ct1;
  Uint8List? _encaps;
  BraidEncoder? _headerEncoder;
  BraidEncoder? _ekEncoder;
  BraidEncoder? _ct1Encoder;
  BraidEncoder? _ct2Encoder;
  BraidDecoder? _headerDecoder;
  BraidDecoder? _ct1Decoder;
  BraidDecoder? _ekDecoder;
  BraidDecoder? _ct2Decoder;

  /// Spec state name. Useful when a session stops making progress.
  String get phase => _phase.name;

  bool get isClosed => _dead;

  Future<BraidSend> send({int chunks = 1}) => _guard(() => _sendMany(chunks));

  Future<BraidReceive> receive(BraidMessage message) =>
      _guard(() => _receive(message));

  /// Zeros the decapsulation key, the encapsulation secret, and the MAC key.
  void wipe() {
    _dead = true;
    _wipeSecrets();
  }

  /// Local session record. The expanded decapsulation key is not written.
  /// A live epoch stores the 64-byte seed and is re-expanded by [fromBytes].
  Uint8List toBytes() {
    if (_dead) throw StateError('The braid session is closed.');
    final builder = BytesBuilder();
    builder.add(const [0x42, 0x52, 0x44, 0x31]);
    builder.addByte(1);
    final epoch = Uint8List(8);
    var value = _epoch;
    for (var i = 7; i >= 0; i--) {
      epoch[i] = value & 0xff;
      value >>= 8;
    }
    builder.add(epoch);
    builder.addByte(_phase.index);
    builder.add(Uint8List.fromList(_auth.root));
    builder.add(Uint8List.fromList(_auth.mac));
    var flags = 0;
    if (_seed != null) flags |= 1;
    if (_ekSeed != null) flags |= 2;
    if (_ekVector != null) flags |= 4;
    if (_hek != null) flags |= 8;
    if (_ct1 != null) flags |= 16;
    if (_encaps != null) flags |= 32;
    builder.addByte(flags);
    if (_seed != null) _addBlob(builder, _seed!);
    if (_ekSeed != null) _addBlob(builder, _ekSeed!);
    if (_ekVector != null) _addBlob(builder, _ekVector!);
    if (_hek != null) _addBlob(builder, _hek!);
    if (_ct1 != null) _addBlob(builder, _ct1!);
    if (_encaps != null) _addBlob(builder, _encaps!);
    final encoders = <(int, BraidEncoder)>[
      if (_headerEncoder != null) (1, _headerEncoder!),
      if (_ekEncoder != null) (2, _ekEncoder!),
      if (_ct1Encoder != null) (3, _ct1Encoder!),
      if (_ct2Encoder != null) (4, _ct2Encoder!),
    ];
    builder.addByte(encoders.length);
    for (final entry in encoders) {
      builder.addByte(entry.$1);
      builder.add(_u32(entry.$2.nextIndex));
      _addBlob(builder, entry.$2.message);
    }
    final decoders = <(int, BraidDecoder)>[
      if (_headerDecoder != null) (1, _headerDecoder!),
      if (_ekDecoder != null) (2, _ekDecoder!),
      if (_ct1Decoder != null) (3, _ct1Decoder!),
      if (_ct2Decoder != null) (4, _ct2Decoder!),
    ];
    builder.addByte(decoders.length);
    for (final entry in decoders) {
      builder.addByte(entry.$1);
      final stored = entry.$2.stored;
      builder.add(_u32(stored.length));
      for (final chunk in stored) {
        builder.add(_u32(chunk.index));
        builder.add(chunk.bytes);
      }
    }
    final bytes = builder.takeBytes();
    return bytes;
  }

  /// Restores [toBytes]. Re-expands a stored seed. Does not accept an
  /// expanded decapsulation key.
  static Future<MlKemBraid> fromBytes(
    Uint8List bytes, {
    bool offload = true,
    Uint8List Function(int length)? randomBytes,
  }) async {
    final reader = _BraidReader(bytes);
    final magic = reader.take(4);
    if (magic[0] != 0x42 ||
        magic[1] != 0x52 ||
        magic[2] != 0x44 ||
        magic[3] != 0x31 ||
        reader.u8() != 1) {
      throw const PqForgeException('Not an ML-KEM Braid session');
    }
    final epoch = reader.u64();
    final phase = _Phase.values[reader.u8()];
    final auth = _Auth(reader.secret32(), reader.secret32());
    final flags = reader.u8();
    final seed = (flags & 1) == 0 ? null : reader.blob();
    final ekSeed = (flags & 2) == 0 ? null : reader.blob();
    final ekVector = (flags & 4) == 0 ? null : reader.blob();
    final hek = (flags & 8) == 0 ? null : reader.blob();
    final ct1 = (flags & 16) == 0 ? null : reader.blob();
    final encaps = (flags & 32) == 0 ? null : reader.blob();
    if (seed != null && seed.length != 64) {
      throw const PqForgeException('ML-KEM Braid seed is not 64 bytes');
    }
    final session = MlKemBraid._(
      epoch: epoch,
      phase: phase,
      auth: auth,
      randomBytes: randomBytes,
      offload: offload,
    );
    session._seed = seed == null ? null : Uint8List.fromList(seed);
    session._ekSeed = _copy(ekSeed);
    session._ekVector = _copy(ekVector);
    session._hek = _copy(hek);
    session._ct1 = _copy(ct1);
    session._encaps = _copy(encaps);
    final encoderCount = reader.u8();
    for (var i = 0; i < encoderCount; i++) {
      final tag = reader.u8();
      final index = reader.u32();
      final message = reader.blob();
      final encoder = BraidEncoder.resume(message, index);
      switch (tag) {
        case 1:
          session._headerEncoder = encoder;
        case 2:
          session._ekEncoder = encoder;
        case 3:
          session._ct1Encoder = encoder;
        case 4:
          session._ct2Encoder = encoder;
        default:
          throw const PqForgeException('Unknown braid encoder');
      }
    }
    final decoderCount = reader.u8();
    for (var i = 0; i < decoderCount; i++) {
      final tag = reader.u8();
      final count = reader.u32();
      final first = count == 0 ? null : _chunk(reader);
      final messageBytes = _decoderLength(tag);
      final decoder = BraidErasure.decoder(messageBytes);
      if (first != null) decoder.add(first);
      for (var n = 1; n < count; n++) {
        decoder.add(_chunk(reader));
      }
      switch (tag) {
        case 1:
          session._headerDecoder = decoder;
        case 2:
          session._ekDecoder = decoder;
        case 3:
          session._ct1Decoder = decoder;
        case 4:
          session._ct2Decoder = decoder;
        default:
          throw const PqForgeException('Unknown braid decoder');
      }
    }
    if (!reader.done) {
      throw const PqForgeException('Trailing bytes on an ML-KEM Braid session');
    }
    if (seed != null) {
      final keys = await MlKemIncremental.keyGen(seed: seed, offload: offload);
      session._dk = Uint8List.fromList(keys.decapsulationKey);
      keys.wipe();
    }
    return session;
  }

  static int _decoderLength(int tag) => switch (tag) {
    1 => _headerBytes,
    2 => MlKemIncremental.ekVectorBytes,
    3 => MlKemIncremental.ct1Bytes,
    4 => _ct2Bytes,
    _ => throw const PqForgeException('Unknown braid decoder'),
  };

  static BraidChunk _chunk(_BraidReader reader) {
    final index = reader.u32();
    return BraidChunk(index, reader.take(BraidErasure.chunkBytes));
  }

  static Uint8List? _copy(Uint8List? bytes) =>
      bytes == null ? null : Uint8List.fromList(bytes);

  static void _addBlob(BytesBuilder builder, Uint8List bytes) {
    _rejectExpanded(bytes);
    builder.add(_u32(bytes.length));
    builder.add(bytes);
  }

  static void _rejectExpanded(Uint8List bytes) {
    if (bytes.length == 1632 || bytes.length == 2400 || bytes.length == 3168) {
      throw const PqForgeException(
        'An expanded ML-KEM private key cannot be a braid session field',
      );
    }
  }

  static Uint8List _u32(int value) {
    final bytes = Uint8List(4);
    ByteData.sublistView(bytes).setUint32(0, value);
    return bytes;
  }

  Future<T> _guard<T>(Future<T> Function() body) async {
    if (_dead) {
      throw const PqForgeException('The braid session is closed.');
    }
    if (_busy) throw StateError('MlKemBraid is already running');
    _busy = true;
    try {
      return await body();
    } finally {
      _busy = false;
    }
  }

  Future<BraidSend> _sendMany(int chunks) async {
    if (chunks < 1 || chunks > 64) {
      throw ArgumentError.value(chunks, 'chunks', '1 to 64');
    }
    final first = await _send();
    if (chunks == 1) return first;
    final messages = <BraidMessage>[first.message];
    for (var i = 1; i < chunks && _pullsChunk; i++) {
      messages.add((await _send()).message);
    }
    return BraidSend.many(messages, first.sendingEpoch, first.output);
  }

  bool get _pullsChunk => switch (_phase) {
    _Phase.keysSampled ||
    _Phase.headerSent ||
    _Phase.ct1Received ||
    _Phase.ct1Sampled ||
    _Phase.ekReceivedCt1Sampled ||
    _Phase.ct2Sampled => true,
    _ => false,
  };

  Future<BraidSend> _send() async {
    switch (_phase) {
      case _Phase.keysUnsampled:
        return _sendFreshKey();
      case _Phase.keysSampled:
        return _sendChunk(_headerEncoder!, BraidMessageType.hdr);
      case _Phase.headerSent:
        return _sendChunk(_ekEncoder!, BraidMessageType.ek);
      case _Phase.ct1Received:
        return _sendChunk(_ekEncoder!, BraidMessageType.ekCt1Ack);
      case _Phase.ct1Sampled:
      case _Phase.ekReceivedCt1Sampled:
        return _sendChunk(_ct1Encoder!, BraidMessageType.ct1);
      case _Phase.ct2Sampled:
        return _sendChunk(_ct2Encoder!, BraidMessageType.ct2);
      case _Phase.headerReceived:
        return _sendEncaps1();
      case _Phase.ekSentCt1Received:
      case _Phase.noHeaderReceived:
      case _Phase.ct1Acknowledged:
        return BraidSend(_bare(BraidMessageType.none), _epoch - 1, null);
    }
  }

  Future<BraidSend> _sendFreshKey() async {
    final material = _seed64();
    _wipe(_seed);
    _seed = Uint8List.fromList(material);
    final keys = await MlKemIncremental.keyGen(
      seed: material,
      offload: _offload,
    );
    secureZero(material);
    _dk = Uint8List.fromList(keys.decapsulationKey);
    _ekSeed = Uint8List.fromList(keys.ekSeed);
    _ekVector = Uint8List.fromList(keys.ekVector);
    _hek = Uint8List.fromList(keys.hek);
    keys.wipe();
    final header = Uint8List(MlKemIncremental.headerBytes);
    header.setRange(0, 32, _ekSeed!);
    header.setRange(32, 64, _hek!);
    final mac = _auth.macHeader(_epoch, header);
    final blob = Uint8List(_headerBytes);
    blob.setRange(0, 64, header);
    blob.setRange(64, blob.length, mac);
    secureZero(mac);
    _headerEncoder = BraidErasure.encoder(blob);
    _phase = _Phase.keysSampled;
    return _sendChunk(_headerEncoder!, BraidMessageType.hdr);
  }

  Future<BraidSend> _sendEncaps1() async {
    final drawn = _draw(32);
    final encapsulated = await MlKemIncremental.encaps1(
      ekSeed: _ekSeed!,
      hek: _hek!,
      coins: drawn,
      offload: _offload,
    );
    if (drawn != null) secureZero(drawn);
    final output = _acceptSecret(encapsulated.sharedSecret);
    _encaps = Uint8List.fromList(encapsulated.encapsSecret);
    _ct1 = Uint8List.fromList(encapsulated.ct1);
    encapsulated.wipe();
    _ct1Encoder = BraidErasure.encoder(_ct1!);
    _phase = _Phase.ct1Sampled;
    final chunk = _ct1Encoder!.next();
    return BraidSend(
      _withChunk(BraidMessageType.ct1, chunk),
      _epoch - 1,
      output,
    );
  }

  BraidSend _sendChunk(BraidEncoder encoder, BraidMessageType type) {
    final chunk = encoder.next();
    return BraidSend(_withChunk(type, chunk), _epoch - 1, null);
  }

  Future<BraidReceive> _receive(BraidMessage message) async {
    switch (_phase) {
      case _Phase.keysUnsampled:
      case _Phase.headerReceived:
        return BraidReceive(_epoch - 1, null);
      case _Phase.keysSampled:
        return _receiveFirstCt1(message);
      case _Phase.headerSent:
        return _receiveMoreCt1(message);
      case _Phase.ct1Received:
        return _receiveFirstCt2(message);
      case _Phase.ekSentCt1Received:
        return _receiveRestCt2(message);
      case _Phase.noHeaderReceived:
        return _receiveHeader(message);
      case _Phase.ct1Sampled:
        return _receiveEkWhileSendingCt1(message);
      case _Phase.ekReceivedCt1Sampled:
        return _receiveAckAfterEk(message);
      case _Phase.ct1Acknowledged:
        return _receiveRestEk(message);
      case _Phase.ct2Sampled:
        if (message.epoch == _epoch + 1) {
          _phase = _Phase.keysUnsampled;
          _epoch += 1;
          _ct2Encoder = null;
        }
        return BraidReceive(_epoch - 1, null);
    }
  }

  BraidReceive _receiveFirstCt1(BraidMessage message) {
    if (message.epoch == _epoch && message.type == BraidMessageType.ct1) {
      _ct1Decoder = BraidErasure.decoder(MlKemIncremental.ct1Bytes);
      _add(_ct1Decoder!, message);
      _ekEncoder = BraidErasure.encoder(_ekVector!);
      _headerEncoder = null;
      _phase = _Phase.headerSent;
    }
    return BraidReceive(_epoch - 1, null);
  }

  BraidReceive _receiveMoreCt1(BraidMessage message) {
    if (message.epoch == _epoch && message.type == BraidMessageType.ct1) {
      _add(_ct1Decoder!, message);
      final ct1 = _ct1Decoder!.message();
      if (ct1 != null) {
        _ct1 = ct1;
        _ct1Decoder = null;
        _phase = _Phase.ct1Received;
      }
    }
    return BraidReceive(_epoch - 1, null);
  }

  BraidReceive _receiveFirstCt2(BraidMessage message) {
    if (message.epoch == _epoch && message.type == BraidMessageType.ct2) {
      _ct2Decoder = BraidErasure.decoder(_ct2Bytes);
      _add(_ct2Decoder!, message);
      _ekEncoder = null;
      _phase = _Phase.ekSentCt1Received;
    }
    return BraidReceive(_epoch - 1, null);
  }

  Future<BraidReceive> _receiveRestCt2(BraidMessage message) async {
    final receiving = _epoch - 1;
    if (message.epoch != _epoch || message.type != BraidMessageType.ct2) {
      return BraidReceive(receiving, null);
    }
    _add(_ct2Decoder!, message);
    final blob = _ct2Decoder!.message();
    if (blob == null) return BraidReceive(receiving, null);
    final ct2 = Uint8List.sublistView(blob, 0, MlKemIncremental.ct2Bytes);
    final mac = Uint8List.sublistView(blob, MlKemIncremental.ct2Bytes);
    final raw = await MlKemIncremental.decaps(
      decapsulationKey: _dk!,
      ct1: _ct1!,
      ct2: ct2,
      offload: _offload,
    );
    final output = _acceptSecret(raw);
    secureZero(raw);
    final body = _ctBody(_ct1!, ct2);
    final expected = _auth.macCiphertext(_epoch, body);
    secureZero(body);
    if (!_same(expected, mac)) {
      secureZero(expected);
      secureZero(output.key);
      _fail();
    }
    secureZero(expected);
    _dropDecapsulation();
    _ct1 = null;
    _ct2Decoder = null;
    _epoch += 1;
    _phase = _Phase.noHeaderReceived;
    _headerDecoder = BraidErasure.decoder(_headerBytes);
    return BraidReceive(receiving, output);
  }

  BraidReceive _receiveHeader(BraidMessage message) {
    if (message.epoch != _epoch || message.type != BraidMessageType.hdr) {
      return BraidReceive(_epoch - 1, null);
    }
    _add(_headerDecoder!, message);
    final blob = _headerDecoder!.message();
    if (blob == null) return BraidReceive(_epoch - 1, null);
    final header = Uint8List.sublistView(blob, 0, 64);
    final mac = Uint8List.sublistView(blob, 64);
    if (!_auth.headerAuthentic(_epoch, header, mac)) _fail();
    _ekSeed = Uint8List.fromList(Uint8List.sublistView(header, 0, 32));
    _hek = Uint8List.fromList(Uint8List.sublistView(header, 32, 64));
    _ekDecoder = BraidErasure.decoder(MlKemIncremental.ekVectorBytes);
    _headerDecoder = null;
    _phase = _Phase.headerReceived;
    return BraidReceive(_epoch - 1, null);
  }

  Future<BraidReceive> _receiveEkWhileSendingCt1(BraidMessage message) async {
    if (message.epoch != _epoch) return BraidReceive(_epoch - 1, null);
    if (message.type == BraidMessageType.ek) {
      _add(_ekDecoder!, message);
      final vector = _ekDecoder!.message();
      if (vector != null) _holdVector(vector);
      return BraidReceive(_epoch - 1, null);
    }
    if (message.type != BraidMessageType.ekCt1Ack) {
      return BraidReceive(_epoch - 1, null);
    }
    _add(_ekDecoder!, message);
    final vector = _ekDecoder!.message();
    if (vector == null) {
      _ct1Encoder = null;
      _phase = _Phase.ct1Acknowledged;
      return BraidReceive(_epoch - 1, null);
    }
    _requireHek(vector);
    return _finishEncaps(vector);
  }

  Future<BraidReceive> _receiveAckAfterEk(BraidMessage message) async {
    if (message.epoch == _epoch && message.type == BraidMessageType.ekCt1Ack) {
      return _finishEncaps(_ekVector!);
    }
    return BraidReceive(_epoch - 1, null);
  }

  Future<BraidReceive> _receiveRestEk(BraidMessage message) async {
    if (message.epoch != _epoch || message.type != BraidMessageType.ekCt1Ack) {
      return BraidReceive(_epoch - 1, null);
    }
    _add(_ekDecoder!, message);
    final vector = _ekDecoder!.message();
    if (vector == null) return BraidReceive(_epoch - 1, null);
    _requireHek(vector);
    return _finishEncaps(vector);
  }

  void _holdVector(Uint8List vector) {
    _requireHek(vector);
    _ekVector = Uint8List.fromList(vector);
    _ekDecoder = null;
    _phase = _Phase.ekReceivedCt1Sampled;
  }

  void _requireHek(Uint8List vector) {
    final got = _hash(_ekSeed!, vector);
    if (!_same(got, _hek!)) {
      secureZero(got);
      _fail();
    }
    secureZero(got);
  }

  Future<BraidReceive> _finishEncaps(Uint8List vector) async {
    final ct2 = await MlKemIncremental.encaps2(
      encapsSecret: _encaps!,
      ekSeed: _ekSeed!,
      ekVector: vector,
      offload: _offload,
    );
    _wipe(_encaps);
    _encaps = null;
    final body = _ctBody(_ct1!, ct2);
    final mac = _auth.macCiphertext(_epoch, body);
    secureZero(body);
    final blob = Uint8List(_ct2Bytes);
    blob.setRange(0, ct2.length, ct2);
    blob.setRange(ct2.length, blob.length, mac);
    secureZero(mac);
    _ct2Encoder = BraidErasure.encoder(blob);
    _ct1Encoder = null;
    _ekDecoder = null;
    _ekVector = null;
    _phase = _Phase.ct2Sampled;
    return BraidReceive(_epoch - 1, null);
  }

  BraidOutput _acceptSecret(Uint8List raw) {
    final mixed = SpqrKdf.sckaKey(raw, epoch: _epoch);
    _auth.update(_epoch, mixed);
    final output = BraidOutput(_epoch, mixed);
    secureZero(mixed);
    return output;
  }

  BraidMessage _withChunk(BraidMessageType type, BraidChunk chunk) {
    return BraidMessage(
      epoch: _epoch,
      type: type,
      index: chunk.index,
      chunk: chunk.bytes,
    );
  }

  BraidMessage _bare(BraidMessageType type) =>
      BraidMessage(epoch: _epoch, type: type);

  Uint8List? _draw(int n) {
    final draw = _randomBytes;
    if (draw == null) return null;
    final out = draw(n);
    if (out.length != n) {
      throw StateError('Braid random returned ${out.length} bytes, wanted $n');
    }
    return Uint8List.fromList(out);
  }

  void _add(BraidDecoder decoder, BraidMessage message) {
    final index = message.index;
    final chunk = message.chunk;
    if (index == null || chunk == null) {
      throw ArgumentError('Braid message is missing its chunk');
    }
    try {
      decoder.add(BraidChunk(index, chunk));
    } on StateError {
      _fail();
    }
  }

  Never _fail() {
    _dead = true;
    _wipeSecrets();
    throw const PqForgeException('No secret was derived.');
  }

  void _wipeSecrets() {
    _dropDecapsulation();
    _wipe(_encaps);
    _encaps = null;
    _auth.wipe();
  }

  void _dropDecapsulation() {
    _wipe(_dk);
    _wipe(_seed);
    _dk = null;
    _seed = null;
  }

  Uint8List _seed64() {
    final drawn = _draw(64);
    if (drawn != null) return drawn;
    final out = Uint8List(64);
    final random = Random.secure();
    for (var i = 0; i < out.length; i++) {
      out[i] = random.nextInt(256);
    }
    return out;
  }

  static void _wipe(Uint8List? bytes) {
    if (bytes != null) secureZero(bytes);
  }
}

const _headerBytes = MlKemIncremental.headerBytes + 32;
const _ct2Bytes = MlKemIncremental.ct2Bytes + 32;

Uint8List _ctBody(Uint8List ct1, Uint8List ct2) {
  final out = Uint8List(ct1.length + ct2.length);
  out.setRange(0, ct1.length, ct1);
  out.setRange(ct1.length, out.length, ct2);
  return out;
}

Uint8List _hash(Uint8List seed, Uint8List vector) {
  final input = Uint8List(seed.length + vector.length);
  input.setRange(0, seed.length, seed);
  input.setRange(seed.length, input.length, vector);
  try {
    return sha3256(input);
  } finally {
    secureZero(input);
  }
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

final class _Auth {
  _Auth(this.root, this.mac);

  factory _Auth.init(Uint8List sharedSecret) {
    final secret = PqRatchetSecrets.copy32('sharedSecret', sharedSecret);
    final zeros = Uint8List(32);
    try {
      final first = SpqrKdf.authenticator(
        rootKey: zeros,
        updateKey: secret,
        epoch: 1,
      );
      return _Auth(first.root, first.mac);
    } finally {
      secureZero(secret);
      secureZero(zeros);
    }
  }

  Uint8List root;
  Uint8List mac;
  bool _wiped = false;

  void update(int epoch, Uint8List key) {
    final next = SpqrKdf.authenticator(
      rootKey: root,
      updateKey: key,
      epoch: epoch,
    );
    secureZero(root);
    secureZero(mac);
    root = next.root;
    mac = next.mac;
  }

  Uint8List macHeader(int epoch, Uint8List header) =>
      _tag(':ekheader', epoch, header);

  Uint8List macCiphertext(int epoch, Uint8List ciphertext) =>
      _tag(':ciphertext', epoch, ciphertext);

  bool headerAuthentic(int epoch, Uint8List header, Uint8List mac) {
    final got = macHeader(epoch, header);
    final ok = _same(got, mac);
    secureZero(got);
    return ok;
  }

  Uint8List _tag(String label, int epoch, Uint8List body) {
    final prefix = _ascii('${SpqrKdf.braidProtocolInfo}$label');
    final epochBytes = SpqrKdf.epochBytes(epoch);
    final message = Uint8List(prefix.length + epochBytes.length + body.length);
    message.setRange(0, prefix.length, prefix);
    message.setRange(
      prefix.length,
      prefix.length + epochBytes.length,
      epochBytes,
    );
    message.setRange(prefix.length + epochBytes.length, message.length, body);
    try {
      return hmacSha256(mac, message);
    } finally {
      secureZero(message);
    }
  }

  void wipe() {
    if (_wiped) return;
    _wiped = true;
    secureZero(root);
    secureZero(mac);
  }
}

Uint8List _ascii(String value) => Uint8List.fromList(utf8.encode(value));

final class _BraidReader {
  _BraidReader(this.bytes);

  final Uint8List bytes;
  int _offset = 0;

  bool get done => _offset == bytes.length;

  Uint8List take(int length) {
    if (_offset + length > bytes.length) {
      throw const PqForgeException('Truncated ML-KEM Braid session');
    }
    final out = Uint8List.sublistView(bytes, _offset, _offset + length);
    _offset += length;
    return Uint8List.fromList(out);
  }

  int u8() => take(1)[0];

  int u32() => ByteData.sublistView(take(4)).getUint32(0);

  int u64() {
    final raw = take(8);
    var value = 0;
    for (final byte in raw) {
      value = (value << 8) | byte;
    }
    return value;
  }

  Uint8List secret32() {
    final bytes = take(32);
    if (bytes.length == 2400) {
      throw const PqForgeException(
        'An expanded ML-KEM private key cannot be a braid session field',
      );
    }
    return bytes;
  }

  Uint8List blob() {
    final length = u32();
    if (length == 1632 || length == 2400 || length == 3168) {
      throw const PqForgeException(
        'An expanded ML-KEM private key cannot be a braid session field',
      );
    }
    return take(length);
  }
}
