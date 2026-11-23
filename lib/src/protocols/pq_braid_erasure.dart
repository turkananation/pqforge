/// Systematic Reed-Solomon over GF(2^16) for ML-KEM Braid chunks.
///
/// A chunk is 32 bytes: 16 little-endian field elements. The codeword index
/// is not one of those bytes. The no-loss path copies the message. Parity
/// uses [Int32x4], four coefficients at a time. The polynomial is
/// x^16 + x^5 + x^3 + x^2 + 1. A 16-bit element fits in a signed lane, which
/// an Ed25519 limb product does not.
library;

import 'dart:typed_data';

/// Encoder and decoder for one braid message.
abstract final class BraidErasure {
  /// Symbol payload. The index travels beside this, not inside it.
  static const chunkBytes = 32;

  /// Distinct codewords. The field has 65536 elements.
  static const maxCodewords = 65536;

  static BraidEncoder encoder(Uint8List message) => BraidEncoder(message);

  static BraidDecoder decoder(int messageBytes) => BraidDecoder(messageBytes);
}

/// Stateful systematic encoder. [next] walks index 0, 1, 2, ...
final class BraidEncoder {
  BraidEncoder(Uint8List message) : _message = Uint8List.fromList(message) {
    if (message.isEmpty || message.length % BraidErasure.chunkBytes != 0) {
      throw ArgumentError.value(
        message.length,
        'message',
        'length must be a positive multiple of ${BraidErasure.chunkBytes}',
      );
    }
    _chunks = message.length ~/ BraidErasure.chunkBytes;
    if (_chunks >= BraidErasure.maxCodewords) {
      throw ArgumentError.value(_chunks, 'message', 'too many chunks');
    }
  }

  final Uint8List _message;
  late final int _chunks;
  int _index = 0;

  /// Next codeword index. The session record stores this, not the parity.
  int get nextIndex => _index;

  /// The message this encoder is walking. A copy.
  Uint8List get message => Uint8List.fromList(_message);

  /// Restores an encoder that has already emitted [index] codewords.
  factory BraidEncoder.resume(Uint8List message, int index) {
    if (index < 0) {
      throw ArgumentError.value(index, 'index', 'negative');
    }
    return BraidEncoder(message).._index = index;
  }

  /// The next codeword. [BraidChunk.bytes] is 32 bytes.
  BraidChunk next() {
    if (_index >= BraidErasure.maxCodewords) {
      throw StateError('Braid erasure encoder exhausted the field');
    }
    final index = _index++;
    if (index < _chunks) {
      final start = index * BraidErasure.chunkBytes;
      return BraidChunk(
        index,
        Uint8List.sublistView(_message, start, start + BraidErasure.chunkBytes),
      );
    }
    final out = Uint8List(BraidErasure.chunkBytes);
    for (var i = 0; i < _chunks; i++) {
      final factor = _inv(i ^ index);
      _scaleXor(
        out,
        Uint8List.sublistView(
          _message,
          i * BraidErasure.chunkBytes,
          (i + 1) * BraidErasure.chunkBytes,
        ),
        factor,
      );
    }
    return BraidChunk(index, out);
  }
}

/// One codeword. [bytes] is a copy when the decoder stores it.
final class BraidChunk {
  BraidChunk(this.index, Uint8List bytes) : bytes = Uint8List.fromList(bytes) {
    if (index < 0 || index >= BraidErasure.maxCodewords) {
      throw ArgumentError.value(index, 'index', 'not a GF(2^16) element');
    }
    if (bytes.length != BraidErasure.chunkBytes) {
      throw ArgumentError.value(
        this.bytes.length,
        'bytes',
        'expected ${BraidErasure.chunkBytes}',
      );
    }
  }

  /// Evaluation index. Not part of [bytes].
  final int index;

  /// Sixteen little-endian GF(2^16) symbols.
  final Uint8List bytes;
}

/// Collects any [BraidErasure] chunks of one message.
final class BraidDecoder {
  BraidDecoder(int messageBytes) : _messageBytes = messageBytes {
    if (messageBytes <= 0 || messageBytes % BraidErasure.chunkBytes != 0) {
      throw ArgumentError.value(
        messageBytes,
        'messageBytes',
        'length must be a positive multiple of ${BraidErasure.chunkBytes}',
      );
    }
    _chunks = messageBytes ~/ BraidErasure.chunkBytes;
  }

  final int _messageBytes;
  late final int _chunks;
  final Map<int, Uint8List> _have = {};

  /// Enough codewords to rebuild the message.
  bool get isComplete => _have.length >= _chunks;

  /// Stored codewords. Each value is a copy.
  List<BraidChunk> get stored => [
    for (final entry in _have.entries) BraidChunk(entry.key, entry.value),
  ];

  /// Ignores an identical repeat. A different payload for the same index throws.
  void add(BraidChunk chunk) {
    final previous = _have[chunk.index];
    if (previous != null) {
      if (!_same(previous, chunk.bytes)) {
        throw StateError('Braid erasure chunk $chunk.index disagrees');
      }
      return;
    }
    _have[chunk.index] = Uint8List.fromList(chunk.bytes);
  }

  /// The message, or null when [isComplete] is false.
  Uint8List? message() {
    if (!isComplete) return null;
    final out = Uint8List(_messageBytes);
    var missing = <int>[];
    for (var i = 0; i < _chunks; i++) {
      final row = _have[i];
      if (row == null) {
        missing.add(i);
      } else {
        out.setRange(
          i * BraidErasure.chunkBytes,
          (i + 1) * BraidErasure.chunkBytes,
          row,
        );
      }
    }
    if (missing.isEmpty) return out;
    final parity = <int>[];
    for (final index in _have.keys) {
      if (index >= _chunks) parity.add(index);
      if (parity.length == missing.length) break;
    }
    if (parity.length < missing.length) return null;
    final width = missing.length;
    final matrix = List.generate(width, (_) => List<int>.filled(width, 0));
    final rhs = List.generate(
      width,
      (_) => List<int>.filled(BraidErasure.chunkBytes ~/ 2, 0),
    );
    for (var row = 0; row < width; row++) {
      final y = parity[row];
      final known = Uint8List(BraidErasure.chunkBytes);
      for (var i = 0; i < _chunks; i++) {
        if (missing.contains(i)) continue;
        _scaleXor(known, _have[i]!, _inv(i ^ y));
      }
      final got = _have[y]!;
      for (var s = 0; s < rhs[row].length; s++) {
        final have = got[s * 2] | (got[s * 2 + 1] << 8);
        final sub = known[s * 2] | (known[s * 2 + 1] << 8);
        rhs[row][s] = have ^ sub;
      }
      for (var col = 0; col < width; col++) {
        matrix[row][col] = _inv(missing[col] ^ y);
      }
    }
    if (!_solve(matrix, rhs)) return null;
    for (var col = 0; col < width; col++) {
      final start = missing[col] * BraidErasure.chunkBytes;
      for (var s = 0; s < rhs[col].length; s++) {
        out[start + s * 2] = rhs[col][s] & 0xff;
        out[start + s * 2 + 1] = (rhs[col][s] >> 8) & 0xff;
      }
    }
    return out;
  }
}

/// GF(2^16) multiply. Exposed to the erasure tests in this library only
/// through [_scaleXor]. Four lanes, schoolbook, reduced by 0x002D.
Int32x4 _mul4(Int32x4 a, Int32x4 b) {
  final reduce = Int32x4(0x002D, 0x002D, 0x002D, 0x002D);
  final one = Int32x4(1, 1, 1, 1);
  final msb = Int32x4(0x8000, 0x8000, 0x8000, 0x8000);
  final mask = Int32x4(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
  var aa = a & mask;
  var bb = b & mask;
  var product = Int32x4.zero();
  for (var i = 0; i < 16; i++) {
    final add = (bb & one).equal(one);
    product = product ^ (aa & add);
    final hi = (aa & msb).equal(msb);
    aa = ((aa << 1) & mask) ^ (reduce & hi);
    bb = bb >>> 1;
  }
  return product;
}

int _mul(int a, int b) {
  final v = _mul4(Int32x4(a, 0, 0, 0), Int32x4(b, 0, 0, 0));
  return v.x & 0xFFFF;
}

int _inv(int a) {
  if (a == 0) {
    throw StateError('GF(2^16) inverse of zero');
  }
  var result = 1;
  var base = a & 0xFFFF;
  var exponent = 65534;
  while (exponent > 0) {
    if (exponent & 1 != 0) result = _mul(result, base);
    base = _mul(base, base);
    exponent >>= 1;
  }
  return result;
}

void _scaleXor(Uint8List acc, Uint8List src, int factor) {
  final scale = Int32x4(factor, factor, factor, factor);
  final data = ByteData.sublistView(acc);
  final from = ByteData.sublistView(src);
  for (var offset = 0; offset < BraidErasure.chunkBytes; offset += 8) {
    final left = Int32x4(
      data.getUint16(offset, Endian.little),
      data.getUint16(offset + 2, Endian.little),
      data.getUint16(offset + 4, Endian.little),
      data.getUint16(offset + 6, Endian.little),
    );
    final right = Int32x4(
      from.getUint16(offset, Endian.little),
      from.getUint16(offset + 2, Endian.little),
      from.getUint16(offset + 4, Endian.little),
      from.getUint16(offset + 6, Endian.little),
    );
    final mixed = left ^ _mul4(right, scale);
    data.setUint16(offset, mixed.x & 0xFFFF, Endian.little);
    data.setUint16(offset + 2, mixed.y & 0xFFFF, Endian.little);
    data.setUint16(offset + 4, mixed.z & 0xFFFF, Endian.little);
    data.setUint16(offset + 6, mixed.w & 0xFFFF, Endian.little);
  }
}

bool _solve(List<List<int>> matrix, List<List<int>> rhs) {
  final width = matrix.length;
  final symbols = rhs[0].length;
  for (var col = 0; col < width; col++) {
    var pivot = col;
    while (pivot < width && matrix[pivot][col] == 0) {
      pivot++;
    }
    if (pivot == width) return false;
    if (pivot != col) {
      final row = matrix[col];
      matrix[col] = matrix[pivot];
      matrix[pivot] = row;
      final side = rhs[col];
      rhs[col] = rhs[pivot];
      rhs[pivot] = side;
    }
    final scale = _inv(matrix[col][col]);
    for (var j = col; j < width; j++) {
      matrix[col][j] = _mul(matrix[col][j], scale);
    }
    for (var j = 0; j < symbols; j++) {
      rhs[col][j] = _mul(rhs[col][j], scale);
    }
    for (var row = 0; row < width; row++) {
      if (row == col) continue;
      final factor = matrix[row][col];
      if (factor == 0) continue;
      for (var j = col; j < width; j++) {
        matrix[row][j] ^= _mul(factor, matrix[col][j]);
      }
      for (var j = 0; j < symbols; j++) {
        rhs[row][j] ^= _mul(factor, rhs[col][j]);
      }
    }
  }
  return true;
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
