import 'dart:typed_data';

/// Why a DER walk stopped. The certificate parser maps these.
enum DerFailure { truncated, notDer, depth, tooLarge }

final class DerSlice {
  DerSlice(this.bytes, this.header, this.start, this.end);

  final Uint8List bytes;

  /// Offset of the tag byte.
  final int header;

  /// Offset of the first value byte.
  final int start;

  /// Offset one past the value.
  final int end;

  int get length => end - start;

  Uint8List copy() =>
      Uint8List.fromList(Uint8List.sublistView(bytes, start, end));

  /// Tag, length, and value. This is the TBS encoding a signature covers.
  Uint8List whole() =>
      Uint8List.fromList(Uint8List.sublistView(bytes, header, end));
}

final class DerWalk {
  DerWalk._(this.failure, this.slice);

  const DerWalk.fail(this.failure) : slice = null;

  final DerFailure? failure;
  final DerSlice? slice;

  bool get ok => failure == null;
}

/// One pass over a DER buffer. No node objects. The length is checked
/// before the cursor moves into a value.
final class DerReader {
  DerReader(this.bytes, {this.offset = 0, int? end, this.depth = 0})
    : end = end ?? bytes.length;

  static const int maxDepth = 16;

  final Uint8List bytes;
  int offset;
  final int end;
  final int depth;

  bool get finished => offset == end;

  DerWalk tag(int expected) {
    final header = offset;
    if (depth > maxDepth) return const DerWalk.fail(DerFailure.depth);
    if (offset >= end) return const DerWalk.fail(DerFailure.truncated);
    final tagByte = bytes[offset++];
    if (tagByte != expected) return const DerWalk.fail(DerFailure.notDer);
    final length = _length();
    if (length == null) return const DerWalk.fail(DerFailure.notDer);
    if (length < 0) return const DerWalk.fail(DerFailure.truncated);
    if (offset + length > end) return const DerWalk.fail(DerFailure.truncated);
    final start = offset;
    offset += length;
    return DerWalk._(null, DerSlice(bytes, header, start, offset));
  }

  DerReader nested(DerSlice slice) =>
      DerReader(bytes, offset: slice.start, end: slice.end, depth: depth + 1);

  int? _length() {
    if (offset >= end) return -1;
    final first = bytes[offset++];
    if (first == 0x80) return null;
    if (first < 0x80) return first;
    final count = first & 0x7f;
    if (count == 0 || count > 3) return null;
    if (offset + count > end) return -1;
    if (bytes[offset] == 0) return null;
    var value = 0;
    for (var i = 0; i < count; i++) {
      value = (value << 8) | bytes[offset++];
    }
    if (value < 128 || (count > 1 && value < 1 << ((count - 1) * 8))) {
      return null;
    }
    return value;
  }
}

final class DerWriter {
  final _bytes = BytesBuilder(copy: false);

  Uint8List take() => _bytes.takeBytes();

  void raw(List<int> bytes) => _bytes.add(bytes);

  void tlv(int tag, List<int> value) {
    _bytes.addByte(tag);
    _length(value.length);
    _bytes.add(value);
  }

  void sequence(List<int> contents) => tlv(0x30, contents);

  void integerUnsigned(Uint8List unsigned) {
    final needsSign = unsigned.isEmpty || (unsigned[0] & 0x80) != 0;
    _bytes.addByte(0x02);
    _length(unsigned.length + (needsSign ? 1 : 0));
    if (needsSign) _bytes.addByte(0);
    _bytes.add(unsigned);
  }

  void bitString(Uint8List payload, {int unused = 0}) {
    _bytes.addByte(0x03);
    _length(payload.length + 1);
    _bytes.addByte(unused);
    _bytes.add(payload);
  }

  void oid(List<int> arcs) => tlv(0x06, oidContents(arcs));

  void nullValue() => tlv(0x05, const <int>[]);

  void _length(int length) {
    if (length < 0x80) {
      _bytes.addByte(length);
      return;
    }
    final bytes = <int>[];
    var remaining = length;
    while (remaining > 0) {
      bytes.add(remaining & 0xff);
      remaining >>= 8;
    }
    _bytes.addByte(0x80 | bytes.length);
    for (var i = bytes.length - 1; i >= 0; i--) {
      _bytes.addByte(bytes[i]);
    }
  }
}

Uint8List oidContents(List<int> arcs) {
  final out = BytesBuilder(copy: false);
  _base128(out, arcs[0] * 40 + arcs[1]);
  for (var i = 2; i < arcs.length; i++) {
    _base128(out, arcs[i]);
  }
  return out.takeBytes();
}

void _base128(BytesBuilder out, int value) {
  if (value < 0) {
    throw ArgumentError.value(value, 'arc', 'OID arc is negative');
  }
  final stack = <int>[value & 0x7f];
  var rest = value >> 7;
  while (rest > 0) {
    stack.add(0x80 | (rest & 0x7f));
    rest >>= 7;
  }
  for (var i = stack.length - 1; i >= 0; i--) {
    out.addByte(stack[i]);
  }
}

bool oidIs(Uint8List contents, List<int> arcs) {
  final expected = oidContents(arcs);
  if (contents.length != expected.length) return false;
  for (var i = 0; i < expected.length; i++) {
    if (contents[i] != expected[i]) return false;
  }
  return true;
}

/// Positive minimal INTEGER contents, or null when the encoding is not DER
/// or the unsigned value exceeds [maxBytes].
Uint8List? unsignedInteger(Uint8List contents, {required int maxBytes}) {
  if (contents.isEmpty) return null;
  if (contents.length > 1 && contents[0] == 0 && (contents[1] & 0x80) == 0) {
    return null;
  }
  if ((contents[0] & 0x80) != 0) return null;
  final unsigned = contents[0] == 0
      ? Uint8List.sublistView(contents, 1)
      : contents;
  if (unsigned.isEmpty || unsigned.length > maxBytes) return null;
  var zero = true;
  for (final byte in unsigned) {
    if (byte != 0) zero = false;
  }
  if (zero) return null;
  return Uint8List.fromList(unsigned);
}
