/// Sequential folder packing (Phase 8) — collapse a tree of (often tiny) files
/// into one stream so it can be sealed by a single streaming envelope.
///
/// This cuts both per-file PQC overhead (one KEM encapsulation and one optional
/// signature for the whole folder instead of one per file) and write
/// amplification on eMMC (one sequential pass instead of N small writes). It is
/// bounded-memory throughout: only one chunk buffer is ever resident.
///
/// Pack wire format (sequential, EOF-terminated):
///
/// ```text
/// entry = uint32 pathLen | pathUtf8 | uint64 contentLen | content
/// pack  = entry*
/// ```
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../primitives/pq_primitives.dart';

/// One file to pack: its archive-relative path and its on-disk source path.
class PqPackEntry {
  const PqPackEntry({required this.relativePath, required this.sourcePath});

  final String relativePath;
  final String sourcePath;
}

/// Bounded-memory sequential packer/unpacker for folder trees.
abstract final class PqFolderPack {
  /// Largest accepted archive path length (defensive bound on untrusted input).
  static const maxPathBytes = 4096;

  /// Writes [entries] to [sink] sequentially. Returns the entry count.
  static Future<int> pack({
    required RandomAccessFile sink,
    required List<PqPackEntry> entries,
    int chunkSize = 1 << 20,
  }) async {
    final buffer = Uint8List(chunkSize);
    for (final entry in entries) {
      _requireSafeRelativePath(entry.relativePath);
      final pathBytes = PqBytes.utf8Bytes(entry.relativePath);
      if (pathBytes.length > maxPathBytes) {
        throw PqForgeException(
          'Pack entry path too long: ${entry.relativePath}',
        );
      }
      final source = File(entry.sourcePath);
      final length = await source.length();
      final header =
          (BytesBuilder(copy: false)
                ..add(PqBytes.uint32(pathBytes.length))
                ..add(pathBytes)
                ..add(PqBytes.uint64(length)))
              .toBytes();
      await sink.writeFrom(header);
      final reader = await source.open();
      try {
        var remaining = length;
        while (remaining > 0) {
          final want = remaining < buffer.length ? remaining : buffer.length;
          final n = await reader.readInto(buffer, 0, want);
          if (n <= 0) {
            throw PqForgeException('Short read packing ${entry.relativePath}');
          }
          await sink.writeFrom(buffer, 0, n);
          remaining -= n;
        }
      } finally {
        await reader.close();
      }
    }
    return entries.length;
  }

  /// Emits [entries] as one sequential pack stream — the streaming counterpart
  /// of [pack], for piping straight into an AEAD writer so the plaintext pack
  /// never exists on disk. Bounded memory: one chunk in flight at a time.
  static Stream<List<int>> packStream(
    List<PqPackEntry> entries, {
    int chunkSize = 1 << 20,
  }) async* {
    for (final entry in entries) {
      _requireSafeRelativePath(entry.relativePath);
      final pathBytes = PqBytes.utf8Bytes(entry.relativePath);
      if (pathBytes.length > maxPathBytes) {
        throw PqForgeException(
          'Pack entry path too long: ${entry.relativePath}',
        );
      }
      final source = File(entry.sourcePath);
      final length = await source.length();
      yield (BytesBuilder(copy: false)
            ..add(PqBytes.uint32(pathBytes.length))
            ..add(pathBytes)
            ..add(PqBytes.uint64(length)))
          .toBytes();
      final reader = await source.open();
      try {
        var remaining = length;
        while (remaining > 0) {
          final want = remaining < chunkSize ? remaining : chunkSize;
          // Fresh buffer per chunk: the consumer may hold it across awaits.
          final chunk = Uint8List(want);
          var offset = 0;
          while (offset < want) {
            final n = await reader.readInto(chunk, offset, want);
            if (n <= 0) {
              throw PqForgeException(
                'Short read packing ${entry.relativePath}',
              );
            }
            offset += n;
          }
          remaining -= want;
          yield chunk;
        }
      } finally {
        await reader.close();
      }
    }
  }

  /// Restores a folder tree from a pack [source] stream (e.g. the authenticated
  /// plaintext frames of `PqForgeStreamCipher.decryptStream`) under
  /// [outputDirPath]. Every path is re-validated against traversal.
  ///
  /// Every byte consumed has already been authenticated frame-by-frame, but a
  /// truncated archive is only detectable at stream end — so on **any** failure
  /// the files this call created are removed before the error propagates,
  /// leaving no partial tree behind. Returns the entry count.
  static Future<int> unpackFromStream(
    Stream<Uint8List> source, {
    required String outputDirPath,
  }) async {
    final reader = _StreamByteReader(source);
    final created = <File>[];
    var count = 0;
    try {
      while (true) {
        final pathLenBytes = await reader.readExactlyOrNull(4);
        if (pathLenBytes == null) break; // clean EOF at an entry boundary
        final pathLen = _readUint32(pathLenBytes);
        if (pathLen <= 0 || pathLen > maxPathBytes) {
          throw PqForgeException('Invalid pack entry path length: $pathLen');
        }
        final relativePath = _decodeUtf8(await reader.readExactly(pathLen));
        _requireSafeRelativePath(relativePath);
        final contentLen = _readUint64(await reader.readExactly(8));

        final output = File(_join(outputDirPath, relativePath));
        await output.parent.create(recursive: true);
        final sink = await output.open(mode: FileMode.write);
        created.add(output);
        try {
          var remaining = contentLen;
          while (remaining > 0) {
            final chunk = await reader.readUpTo(remaining);
            if (chunk == null) {
              throw PqForgeException(
                'Truncated pack content for $relativePath',
              );
            }
            await sink.writeFrom(chunk);
            remaining -= chunk.length;
          }
        } finally {
          await sink.close();
        }
        count++;
      }
      return count;
    } catch (_) {
      for (final file in created) {
        try {
          if (file.existsSync()) await file.delete();
        } on FileSystemException {
          // Best effort: never mask the original failure.
        }
      }
      rethrow;
    }
  }

  /// Reads a pack from [source] and materializes each entry under
  /// [outputDirPath]. Every path is re-validated against traversal. Returns the
  /// entry count.
  static Future<int> unpack({
    required RandomAccessFile source,
    required String outputDirPath,
    int chunkSize = 1 << 20,
  }) async {
    final buffer = Uint8List(chunkSize);
    var count = 0;
    while (true) {
      final pathLenBytes = await _readExactlyOrNull(source, 4);
      if (pathLenBytes == null) break; // clean EOF at an entry boundary
      final pathLen = _readUint32(pathLenBytes);
      if (pathLen <= 0 || pathLen > maxPathBytes) {
        throw PqForgeException('Invalid pack entry path length: $pathLen');
      }
      final relativePath = _decodeUtf8(await _readExactly(source, pathLen));
      _requireSafeRelativePath(relativePath);
      final contentLen = _readUint64(await _readExactly(source, 8));

      final output = File(_join(outputDirPath, relativePath));
      await output.parent.create(recursive: true);
      final sink = await output.open(mode: FileMode.write);
      try {
        var remaining = contentLen;
        while (remaining > 0) {
          final want = remaining < buffer.length ? remaining : buffer.length;
          final n = await source.readInto(buffer, 0, want);
          if (n <= 0) {
            throw PqForgeException('Truncated pack content for $relativePath');
          }
          await sink.writeFrom(buffer, 0, n);
          remaining -= n;
        }
      } finally {
        await sink.close();
      }
      count++;
    }
    return count;
  }
}

/// Pull-style reader over a chunked byte stream: lets the pack parser read
/// exact-length headers and bounded content runs without ever buffering more
/// than one upstream chunk.
class _StreamByteReader {
  _StreamByteReader(Stream<Uint8List> source)
    : _iterator = StreamIterator(source);

  final StreamIterator<Uint8List> _iterator;
  Uint8List _current = Uint8List(0);
  int _offset = 0;

  int get _available => _current.length - _offset;

  Future<bool> _refill() async {
    while (_available == 0) {
      if (!await _iterator.moveNext()) return false;
      _current = _iterator.current;
      _offset = 0;
    }
    return true;
  }

  /// Reads exactly [length] bytes, or returns null on a clean EOF at a
  /// boundary. Throws on EOF mid-read.
  Future<Uint8List?> readExactlyOrNull(int length) async {
    final out = Uint8List(length);
    var written = 0;
    while (written < length) {
      if (!await _refill()) {
        if (written == 0) return null;
        throw const PqForgeException('Truncated pack entry header');
      }
      final n = _available < (length - written) ? _available : length - written;
      out.setRange(written, written + n, _current, _offset);
      _offset += n;
      written += n;
    }
    return out;
  }

  /// Reads exactly [length] bytes; throws on any EOF.
  Future<Uint8List> readExactly(int length) async {
    final out = await readExactlyOrNull(length);
    if (out == null) {
      throw const PqForgeException('Unexpected end of pack stream');
    }
    return out;
  }

  /// Returns the next run of available bytes (at most [max]) as a view, or
  /// null on EOF. The view is only valid until the next read call.
  Future<Uint8List?> readUpTo(int max) async {
    if (!await _refill()) return null;
    final n = _available < max ? _available : max;
    final view = Uint8List.sublistView(_current, _offset, _offset + n);
    _offset += n;
    return view;
  }
}

String _decodeUtf8(Uint8List bytes) {
  try {
    return utf8.decode(bytes);
  } on FormatException {
    throw const PqForgeException('Malformed pack entry path (invalid UTF-8)');
  }
}

void _requireSafeRelativePath(String relativePath) {
  final segments = relativePath.split('/');
  if (relativePath.isEmpty ||
      relativePath.startsWith('/') ||
      relativePath.contains(r'\') ||
      segments.any((s) => s.isEmpty || s == '.' || s == '..')) {
    throw PqForgeException('Unsafe pack relative path: $relativePath');
  }
}

String _join(String root, String relativePath) {
  final base = root.endsWith('/') ? root.substring(0, root.length - 1) : root;
  return '$base/$relativePath';
}

int _readUint32(Uint8List bytes) =>
    bytes.buffer.asByteData(bytes.offsetInBytes, 4).getUint32(0, Endian.big);

// Two uint32 halves via PqBytes.readUint64, keeping the arithmetic portable
// (ByteData.getUint64 throws on dart2js) even though this service is dart:io.
int _readUint64(Uint8List bytes) => PqBytes.readUint64(bytes);

Future<Uint8List> _readExactly(RandomAccessFile source, int length) async {
  final buffer = Uint8List(length);
  var offset = 0;
  while (offset < length) {
    final read = await source.readInto(buffer, offset, length);
    if (read <= 0) {
      throw const PqForgeException('Unexpected end of pack stream');
    }
    offset += read;
  }
  return buffer;
}

Future<Uint8List?> _readExactlyOrNull(
  RandomAccessFile source,
  int length,
) async {
  final buffer = Uint8List(length);
  var offset = 0;
  while (offset < length) {
    final read = await source.readInto(buffer, offset, length);
    if (read <= 0) {
      if (offset == 0) return null;
      throw const PqForgeException('Truncated pack entry header');
    }
    offset += read;
  }
  return buffer;
}
