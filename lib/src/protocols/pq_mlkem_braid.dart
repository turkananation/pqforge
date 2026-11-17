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
  BraidSend(this.message, this.sendingEpoch, this.output);

  final BraidMessage message;
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
    required this._epoch,
    required this._phase,
    required this._auth,
    required this._randomBytes,
    this._headerDecoder,
  });

  /// Alice, epoch 1, ready to sample a key on the first [send].
  factory MlKemBraid.alice(
    Uint8List sharedSecret, {
    Uint8List Function(int length)? randomBytes,
  }) {
    return MlKemBraid._(
      epoch: 1,
      phase: _Phase.keysUnsampled,
      auth: _Auth.init(sharedSecret),
      randomBytes: randomBytes,
    );
  }

  /// Bob, epoch 1, waiting for Alice's header.
  factory MlKemBraid.bob(
    Uint8List sharedSecret, {
    Uint8List Function(int length)? randomBytes,
  }) {
    return MlKemBraid._(
      epoch: 1,
      phase: _Phase.noHeaderReceived,
      auth: _Auth.init(sharedSecret),
      randomBytes: randomBytes,
      headerDecoder: BraidErasure.decoder(_headerBytes),
    );
  }

  final Uint8List Function(int length)? _randomBytes;
  int _epoch;
  _Phase _phase;
  final _Auth _auth;
  bool _dead = false;
  bool _busy = false;

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

  Future<BraidSend> send() => _guard(_send);

  Future<BraidReceive> receive(BraidMessage message) =>
      _guard(() => _receive(message));

  /// Zeros the decapsulation key, the encapsulation secret, and the MAC key.
  void wipe() {
    _dead = true;
    _wipeSecrets();
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
    final drawn = _draw(64);
    final keys = await MlKemIncremental.keyGen(seed: drawn);
    if (drawn != null) secureZero(drawn);
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
    _wipe(_dk);
    _dk = null;
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
    _wipe(_dk);
    _wipe(_encaps);
    _dk = null;
    _encaps = null;
    _auth.wipe();
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
