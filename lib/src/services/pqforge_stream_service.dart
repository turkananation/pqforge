/// Bounded-memory streaming file encryption over the `.pqfs` frame format.
///
/// This is the `dart:io` glue around the pure, web-safe [PqStreamingEnvelope]
/// codec: it walks the input file in fixed-size frames, seals/opens each frame
/// through a [PqForgeAeadEngine], and writes to the output with a working set of
/// roughly two frames — independent of total file length. The KEM, header
/// signing, and AAD policy mirror the one-shot [PqForge] envelope so the two
/// formats share a key schedule.
library;

import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../cipher/pq_cipher_suite.dart';
import '../cipher/pq_cryptography_aead_engine.dart';
import '../cipher/pq_pointycastle_aead_engine.dart';
import '../codecs/pq_envelope.dart';
import '../primitives/pq_primitives.dart';
import 'pqforge_service.dart';

/// Outcome of a streaming encrypt/decrypt: byte and frame counts for logging.
class PqStreamingStats {
  const PqStreamingStats({
    required this.plaintextBytes,
    required this.containerBytes,
    required this.frameCount,
    required this.signed,
  });

  final int plaintextBytes;
  final int containerBytes;
  final int frameCount;
  final bool signed;
}

/// Encrypts and decrypts files in bounded memory using the `.pqfs` streaming
/// envelope. Construct once and reuse; the [engine] is the hardware-acceleration
/// lever (swap in a `package:cryptography` engine without touching this code).
class PqForgeStreamCipher {
  PqForgeStreamCipher({PqForgeAeadEngine? engine})
    : engine =
          engine ??
          const PqForgePointyCastleAeadEngine(PqForgeCipherSuite.aes256Gcm);

  /// Builds a cipher backed by [provider] — the hardware-acceleration lever.
  ///
  /// * [PqForgeEngineProvider.pureDart] (default) — PointyCastle; works on every
  ///   target and inside background isolates.
  /// * [PqForgeEngineProvider.nativeCryptography] — `package:cryptography`, which
  ///   dispatches to AES-NI/ARMv8 when a Flutter host has called
  ///   `FlutterCryptography.enable()`. Note: its platform-channel calls run on
  ///   the root isolate, so use this engine *without* an [Isolate.run] offload.
  factory PqForgeStreamCipher.forProvider(
    PqForgeEngineProvider provider, {
    PqForgeCipherSuite cipherSuite = PqForgeCipherSuite.aes256Gcm,
  }) {
    return PqForgeStreamCipher(
      engine: switch (provider) {
        PqForgeEngineProvider.pureDart => PqForgePointyCastleAeadEngine(
          cipherSuite,
        ),
        PqForgeEngineProvider.nativeCryptography => PqForgeCryptographyAeadEngine(
          cipherSuite,
        ),
      },
    );
  }

  /// The AEAD engine each frame is sealed/opened with.
  final PqForgeAeadEngine engine;

  /// Inputs at or above this size are worth streaming; smaller ones can stay on
  /// the one-shot [PqForge] envelope where the per-file overhead dominates.
  static const streamingThresholdBytes = 8 * 1024 * 1024;

  /// Returns true if [file] begins with the streaming-envelope magic, so a
  /// reader can auto-route between `.pqfs` and one-shot envelopes.
  static Future<bool> isStreamingFile(File file) async {
    final magic = PqBytes.utf8Bytes(PqStreamingEnvelope.magic);
    final raf = await file.open();
    try {
      final head = Uint8List(magic.length);
      final read = await raf.readInto(head);
      if (read < magic.length) return false;
      for (var i = 0; i < magic.length; i++) {
        if (head[i] != magic[i]) return false;
      }
      return true;
    } finally {
      await raf.close();
    }
  }

  /// Runs [encryptFile] on a background isolate so the calling (UI) isolate is
  /// never blocked by the synchronous pure-Dart cipher — the Axis A offload.
  ///
  /// The pure-Dart engine is used inside the isolate (the native engine's
  /// platform channels are unavailable off the root isolate). Arguments are
  /// passed as sendable primitives (paths, key bytes, profile).
  static Future<PqStreamingStats> encryptFileInBackground({
    required Uint8List recipientPublicKey,
    required String inputPath,
    required String outputPath,
    required PqForgeProfile profile,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
    int frameSize = PqStreamingEnvelope.defaultFrameSize,
  }) {
    return Isolate.run(
      () => PqForgeStreamCipher().encryptFile(
        recipientPublicKey: recipientPublicKey,
        input: File(inputPath),
        output: File(outputPath),
        profile: profile,
        aad: aad,
        metadata: metadata,
        signerSecretKey: signerSecretKey,
        signatureAlgorithm: signatureAlgorithm,
        signerKeyId: signerKeyId,
        frameSize: frameSize,
      ),
    );
  }

  /// Runs [decryptFile] on a background isolate (Axis A offload).
  ///
  /// [aad] is the already-resolved associated data; read the header first (see
  /// [readHeader]) when it depends on the envelope's metadata.
  static Future<PqStreamingHeader> decryptFileInBackground({
    required Uint8List recipientSecretKey,
    required String inputPath,
    required String outputPath,
    Uint8List? signerPublicKey,
    Uint8List? aad,
  }) {
    return Isolate.run(
      () => PqForgeStreamCipher().decryptFile(
        recipientSecretKey: recipientSecretKey,
        input: File(inputPath),
        output: File(outputPath),
        signerPublicKey: signerPublicKey,
        aadResolver: aad == null ? null : (_) => aad,
      ),
    );
  }

  /// Streams [input] into a `.pqfs` container at [output].
  ///
  /// When [signerSecretKey] is supplied the header (never the payload) is signed
  /// with `preHash:true`, so signing is O(1) in file size. On failure the partial
  /// [output] is removed.
  Future<PqStreamingStats> encryptFile({
    required Uint8List recipientPublicKey,
    required File input,
    required File output,
    required PqForgeProfile profile,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
    int frameSize = PqStreamingEnvelope.defaultFrameSize,
  }) async {
    final signatureAlg = signerSecretKey == null
        ? signatureAlgorithm
        : (signatureAlgorithm ?? profile.signature);
    final encapsulated = PqKemPrimitives.encapsulate(
      profile.kem,
      recipientPublicKey,
    );
    final demKey = PqForge.deriveDemKey(
      profile,
      encapsulated.sharedSecret,
      encapsulated.ciphertext,
    );
    final header = PqStreamingHeader(
      profile: profile,
      kemAlgorithm: profile.kem,
      signatureAlgorithm: signatureAlg,
      kemCiphertext: encapsulated.ciphertext,
      nonceSalt: PqBytes.randomBytes(PqStreamingEnvelope.nonceSaltBytes),
      frameSize: frameSize,
      aadHash: aad == null ? null : PqBytes.sha256(aad),
      metadata: metadata,
      signerKeyId: signerKeyId,
    );
    final headerCore = PqStreamingEnvelope.serializeHeaderCore(header);
    final headerHash = PqBytes.sha256(headerCore);
    final signature = signerSecretKey == null
        ? Uint8List(0)
        : PqSignaturePrimitives.sign(
            signatureAlg!,
            signerSecretKey,
            headerCore,
            context: PqStreamingEnvelope.signatureContext(),
            preHash: true,
          );

    await output.parent.create(recursive: true);
    final source = await input.open();
    final sink = await output.open(mode: FileMode.write);
    var success = false;
    var containerBytes = 0;
    var plaintextBytes = 0;
    var frameCount = 0;
    try {
      final containerHeader = _buildContainerHeader(headerCore, signature);
      await sink.writeFrom(containerHeader);
      containerBytes += containerHeader.length;

      final total = await source.length();
      final buffer = Uint8List(frameSize);
      var seq = 0;
      var read = 0;
      if (total == 0) {
        // An empty input still gets one (empty) final frame so the reader sees a
        // terminator rather than a truncated stream.
        containerBytes += await _writeFrame(
          sink: sink,
          demKey: demKey,
          headerHash: headerHash,
          nonceSalt: header.nonceSalt,
          seq: 0,
          isFinal: true,
          plaintext: Uint8List(0),
        );
        frameCount = 1;
      } else {
        while (read < total) {
          final n = await source.readInto(buffer);
          if (n <= 0) break;
          final isFinal = (read + n) >= total;
          containerBytes += await _writeFrame(
            sink: sink,
            demKey: demKey,
            headerHash: headerHash,
            nonceSalt: header.nonceSalt,
            seq: seq,
            isFinal: isFinal,
            plaintext: Uint8List.sublistView(buffer, 0, n),
          );
          plaintextBytes += n;
          read += n;
          seq++;
          frameCount++;
        }
      }
      await sink.flush();
      success = true;
      return PqStreamingStats(
        plaintextBytes: plaintextBytes,
        containerBytes: containerBytes,
        frameCount: frameCount,
        signed: signerSecretKey != null,
      );
    } finally {
      await source.close();
      await sink.close();
      if (!success) await _deleteQuietly(output);
    }
  }

  /// Reads and parses the container header without decrypting any frame — useful
  /// for inspecting metadata (e.g. an output filename) before a full decrypt.
  Future<PqStreamingHeader> readHeader(File input) async {
    final source = await input.open();
    try {
      return (await _readContainerHeader(source)).header;
    } finally {
      await source.close();
    }
  }

  /// Streams a `.pqfs` [input] back to plaintext at [output] in bounded memory.
  ///
  /// [aadResolver] builds the expected AAD from the (now header-bound) metadata,
  /// mirroring the recipe binding of the one-shot path. On any failure — a bad
  /// signature, AAD mismatch, tampered/reordered/truncated frame — the partial
  /// [output] is removed before the error propagates.
  Future<PqStreamingHeader> decryptFile({
    required Uint8List recipientSecretKey,
    required File input,
    required File output,
    Uint8List? signerPublicKey,
    Uint8List? Function(PqStreamingHeader header)? aadResolver,
  }) async {
    await output.parent.create(recursive: true);
    final source = await input.open();
    final sink = await output.open(mode: FileMode.write);
    var success = false;
    try {
      final container = await _readContainerHeader(source);
      final header = container.header;

      if (container.signature != null) {
        if (signerPublicKey == null) {
          throw const PqForgeException(
            'signerPublicKey is required for a signed streaming envelope',
          );
        }
        final ok = PqSignaturePrimitives.verify(
          header.signatureAlgorithm!,
          signerPublicKey,
          container.headerCore,
          container.signature!,
          context: PqStreamingEnvelope.signatureContext(),
          preHash: true,
        );
        if (!ok) {
          throw const PqForgeException(
            'ML-DSA streaming header signature verification failed',
          );
        }
      }

      final aad = aadResolver?.call(header);
      if (header.aadHash != null) {
        if (aad == null) {
          throw const PqForgeException(
            'AAD is required for this streaming envelope',
          );
        }
        if (!PqBytes.constantTimeEquals(PqBytes.sha256(aad), header.aadHash!)) {
          throw const PqForgeException('AAD hash mismatch');
        }
      }

      final sharedSecret = PqKemPrimitives.decapsulate(
        header.kemAlgorithm,
        recipientSecretKey,
        header.kemCiphertext,
      );
      final demKey = PqForge.deriveDemKey(
        header.profile,
        sharedSecret,
        header.kemCiphertext,
      );

      final maxBody = header.frameSize + engine.cipherSuite.tagLength;
      var expectedSeq = 0;
      var sawFinal = false;
      while (true) {
        final frameHeader = await _readExactlyOrNull(
          source,
          PqStreamingEnvelope.frameHeaderBytes,
        );
        if (frameHeader == null) break; // clean EOF at a frame boundary
        if (sawFinal) {
          throw const PqForgeException(
            'Trailing data after the final streaming frame',
          );
        }
        final parsed = PqStreamingEnvelope.parseFrameHeader(frameHeader);
        if (parsed.seq != expectedSeq) {
          throw PqForgeException(
            'Streaming frame out of order: expected $expectedSeq, '
            'got ${parsed.seq}',
          );
        }
        if (parsed.bodyLen < engine.cipherSuite.tagLength ||
            parsed.bodyLen > maxBody) {
          throw PqForgeException(
            'Invalid streaming frame body length: ${parsed.bodyLen}',
          );
        }
        final body = await _readExactly(source, parsed.bodyLen);
        final plaintext = await PqStreamingEnvelope.openFrameBody(
          engine: engine,
          demKey: demKey,
          headerHash: container.headerHash,
          nonceSalt: header.nonceSalt,
          seq: expectedSeq,
          isFinal: parsed.isFinal,
          body: body,
        );
        if (plaintext.isNotEmpty) await sink.writeFrom(plaintext);
        if (parsed.isFinal) sawFinal = true;
        expectedSeq++;
      }
      if (!sawFinal) {
        throw const PqForgeException(
          'Truncated streaming envelope: missing final frame',
        );
      }
      await sink.flush();
      success = true;
      return header;
    } finally {
      await source.close();
      await sink.close();
      if (!success) await _deleteQuietly(output);
    }
  }

  Future<int> _writeFrame({
    required RandomAccessFile sink,
    required Uint8List demKey,
    required Uint8List headerHash,
    required Uint8List nonceSalt,
    required int seq,
    required bool isFinal,
    required Uint8List plaintext,
  }) async {
    final body = await PqStreamingEnvelope.sealFrameBody(
      engine: engine,
      demKey: demKey,
      headerHash: headerHash,
      nonceSalt: nonceSalt,
      seq: seq,
      isFinal: isFinal,
      plaintext: plaintext,
    );
    final frameHeader = PqStreamingEnvelope.buildFrameHeader(
      bodyLen: body.length,
      seq: seq,
      isFinal: isFinal,
    );
    await sink.writeFrom(frameHeader);
    await sink.writeFrom(body);
    return frameHeader.length + body.length;
  }

  Uint8List _buildContainerHeader(Uint8List headerCore, Uint8List signature) {
    return (BytesBuilder(copy: false)
          ..add(PqBytes.utf8Bytes(PqStreamingEnvelope.magic))
          ..add(PqBytes.uint32(PqStreamingEnvelope.formatVersion))
          ..add(PqBytes.uint32(headerCore.length))
          ..add(headerCore)
          ..add(PqBytes.uint32(signature.length))
          ..add(signature))
        .toBytes();
  }

  Future<_StreamingContainer> _readContainerHeader(
    RandomAccessFile source,
  ) async {
    final magic = PqBytes.utf8Bytes(PqStreamingEnvelope.magic);
    final magicBytes = await _readExactly(source, magic.length);
    for (var i = 0; i < magic.length; i++) {
      if (magicBytes[i] != magic[i]) {
        throw const PqForgeException(
          'Not a pqforge streaming envelope (bad magic)',
        );
      }
    }
    final version = _readUint32(await _readExactly(source, 4));
    if (version != PqStreamingEnvelope.formatVersion) {
      throw PqForgeException(
        'Unsupported streaming envelope version: $version',
      );
    }
    final headerCore = await _readExactly(
      source,
      _readUint32(await _readExactly(source, 4)),
    );
    final signatureLen = _readUint32(await _readExactly(source, 4));
    final signature = signatureLen == 0
        ? null
        : await _readExactly(source, signatureLen);
    return _StreamingContainer(
      header: PqStreamingEnvelope.parseHeaderCore(headerCore),
      headerCore: headerCore,
      signature: signature,
      headerHash: PqBytes.sha256(headerCore),
    );
  }
}

class _StreamingContainer {
  _StreamingContainer({
    required this.header,
    required this.headerCore,
    required this.signature,
    required this.headerHash,
  });

  final PqStreamingHeader header;
  final Uint8List headerCore;
  final Uint8List? signature;
  final Uint8List headerHash;
}

Future<Uint8List> _readExactly(RandomAccessFile source, int length) async {
  final buffer = Uint8List(length);
  var offset = 0;
  while (offset < length) {
    final read = await source.readInto(buffer, offset, length);
    if (read <= 0) {
      throw const PqForgeException('Unexpected end of streaming envelope');
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
      if (offset == 0) return null; // clean EOF exactly at a frame boundary
      throw const PqForgeException('Truncated streaming frame');
    }
    offset += read;
  }
  return buffer;
}

int _readUint32(Uint8List bytes) =>
    bytes.buffer.asByteData(bytes.offsetInBytes, 4).getUint32(0, Endian.big);

Future<void> _deleteQuietly(File file) async {
  try {
    if (file.existsSync()) await file.delete();
  } on FileSystemException {
    // Best effort: never mask the original failure with a cleanup error.
  }
}
