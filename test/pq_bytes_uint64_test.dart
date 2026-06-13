import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

/// R10: the uint64 codec arithmetic is encoded as two uint32 halves so it
/// runs under dart2js — while staying byte-identical to the previous
/// `ByteData.setUint64` wire encoding (proved against the VM oracle here).
/// Also covers the streamed SHA-256 used by digest-mode signing (R1).
void main() {
  group('PqBytes.uint64 / readUint64', () {
    const samples = [
      0,
      1,
      255,
      4096,
      0x7FFFFFFF,
      0x80000000,
      0xFFFFFFFF,
      0x100000000, // 2^32 — first value with a non-zero high half
      0x1FFFFFFFFFFFFF, // 2^53 - 1 — the largest web-exact value
    ];

    test('round-trips every representable sample', () {
      for (final value in samples) {
        expect(
          PqBytes.readUint64(PqBytes.uint64(value)),
          value,
          reason: '$value',
        );
      }
    });

    test('matches the ByteData.setUint64 wire encoding (VM oracle)', () {
      for (final value in samples) {
        final oracle = Uint8List(8)
          ..buffer.asByteData().setUint64(0, value, Endian.big);
        expect(PqBytes.uint64(value), oracle, reason: '$value');
      }
    });

    test('honors a read offset', () {
      final buffer = Uint8List(12)..setRange(4, 12, PqBytes.uint64(0xDEADBEEF));
      expect(PqBytes.readUint64(buffer, 4), 0xDEADBEEF);
    });

    test('rejects values at or above 2^53', () {
      final tooBig = Uint8List(8)
        ..buffer.asByteData().setUint64(0, 1 << 53, Endian.big);
      expect(
        () => PqBytes.readUint64(tooBig),
        throwsA(isA<PqForgeException>()),
      );
    });

    test('rejects negative input', () {
      expect(() => PqBytes.uint64(-1), throwsRangeError);
    });
  });

  group('streaming frame header portability', () {
    test('build/parse round-trips a high sequence number', () {
      final header = PqStreamingEnvelope.buildFrameHeader(
        bodyLen: 0xABCDEF,
        seq: 0xFFFFFFFF,
        isFinal: true,
      );
      final parsed = PqStreamingEnvelope.parseFrameHeader(header);
      expect(parsed.bodyLen, 0xABCDEF);
      expect(parsed.seq, 0xFFFFFFFF);
      expect(parsed.isFinal, isTrue);
    });

    test('frameNonce still enforces the per-key GCM invocation bound', () {
      expect(
        () => PqStreamingEnvelope.frameNonce(
          Uint8List(4),
          PqStreamingEnvelope.maxFrameCount,
        ),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        PqStreamingEnvelope.frameNonce(
          Uint8List(4),
          PqStreamingEnvelope.maxFrameCount - 1,
        ),
        hasLength(12),
      );
    });
  });

  group('PqBytes.sha256OfStream', () {
    test('matches the one-shot digest across chunkings', () async {
      final data = Uint8List.fromList(
        List<int>.generate(65537, (i) => (i * 131 + 17) & 0xFF),
      );
      final whole = PqBytes.sha256(data);
      for (final chunkSize in [1, 7, 1024, 65536, data.length]) {
        final stream = Stream<List<int>>.fromIterable([
          for (var i = 0; i < data.length; i += chunkSize)
            data.sublist(
              i,
              i + chunkSize > data.length ? data.length : i + chunkSize,
            ),
        ]);
        expect(
          await PqBytes.sha256OfStream(stream),
          whole,
          reason: 'chunk size $chunkSize',
        );
      }
    });

    test('hashes the empty stream', () async {
      expect(
        await PqBytes.sha256OfStream(const Stream<List<int>>.empty()),
        PqBytes.sha256(Uint8List(0)),
      );
    });
  });
}
