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
import '../algorithms/pq_fips.dart';
import '../cipher/pq_cipher_suite.dart';
import '../cipher/pq_cryptography_aead_engine.dart';
import '../codecs/pq_streaming_envelope.dart';
import '../primitives/pq_primitives.dart';
import 'pqforge_async_service.dart';
import 'pqforge_multi_recipient.dart';
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
/// lever.
///
/// The default engine is the `package:cryptography` backend: measured ~10×
/// faster than PointyCastle even as pure Dart, and it dispatches to OS-native
/// hardware AEAD when a Flutter host has called `FlutterCryptography.enable()`
/// (root isolate). The wire format is engine-independent — files sealed by one
/// engine open under the other.
class PqForgeStreamCipher {
  PqForgeStreamCipher({PqForgeAeadEngine? engine})
    : engine =
          engine ??
          PqForgeCryptographyAeadEngine(PqForgeCipherSuite.aes256Gcm) {
    PqFipsMode.requireApprovedSuite(this.engine.cipherSuite);
  }

  /// Builds a cipher backed by [provider] — the hardware-acceleration lever.
  ///
  /// * [PqForgeEngineProvider.nativeCryptography] (the default) —
  ///   `package:cryptography`: ~10× faster than PointyCastle even as pure Dart,
  ///   and it dispatches to AES-NI/ARMv8 hardware when a Flutter host has called
  ///   `FlutterCryptography.enable()` (root isolate; fresh isolates fall back to
  ///   its pure-Dart implementation automatically).
  /// * [PqForgeEngineProvider.pureDart] — PointyCastle; the conservative
  ///   reference backend.
  factory PqForgeStreamCipher.forProvider(
    PqForgeEngineProvider provider, {
    PqForgeCipherSuite cipherSuite = PqForgeCipherSuite.aes256Gcm,
  }) {
    return PqForgeStreamCipher(
      engine: aeadEngineForProvider(provider, cipherSuite: cipherSuite),
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
  /// never blocked — the Axis A offload.
  ///
  /// The engine is constructed *inside* the worker isolate from
  /// [engineProvider]. Both providers are safe there: on a plain Dart VM the
  /// `cryptography` backend is its (fast) pure-Dart implementation, and on
  /// Flutter a fresh isolate never sees `FlutterCryptography`'s root-isolate
  /// registration, so it also falls back to pure Dart rather than touching
  /// platform channels. Arguments are sendable primitives (paths, key bytes,
  /// profile).
  static Future<PqStreamingStats> encryptFileInBackground({
    required Uint8List recipientPublicKey,
    required String inputPath,
    required String outputPath,
    required PqForgeProfile profile,
    Uint8List? recipientKexPublicKey,
    List<PqRecipientSpec> additionalRecipients = const [],
    String? recipientKeyId,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
    int frameSize = PqStreamingEnvelope.defaultFrameSize,
    PqForgeEngineProvider engineProvider =
        PqForgeEngineProvider.nativeCryptography,
    PqForgeCipherSuite cipherSuite = PqForgeCipherSuite.aes256Gcm,
  }) {
    return Isolate.run(
      () =>
          PqForgeStreamCipher.forProvider(
            engineProvider,
            cipherSuite: cipherSuite,
          ).encryptFile(
            recipientPublicKey: recipientPublicKey,
            recipientKexPublicKey: recipientKexPublicKey,
            additionalRecipients: additionalRecipients,
            recipientKeyId: recipientKeyId,
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
    Uint8List? recipientKexSecretKey,
    String? recipientKeyId,
    Uint8List? signerPublicKey,
    Uint8List? aad,
    PqForgeEngineProvider engineProvider =
        PqForgeEngineProvider.nativeCryptography,
  }) {
    return Isolate.run(
      () => PqForgeStreamCipher.forProvider(engineProvider).decryptFile(
        recipientSecretKey: recipientSecretKey,
        recipientKexSecretKey: recipientKexSecretKey,
        recipientKeyId: recipientKeyId,
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
  /// with `preHash:true`, so signing is O(1) in file size. When
  /// [recipientKexPublicKey] (a raw 32-byte X25519 public key) is supplied the
  /// container is **hybrid**: the DEM key combines the ML-KEM shared secret
  /// with an ephemeral X25519 exchange (see [PqHybridKemDem]). Each
  /// [additionalRecipients] entry wraps the same DEM key to one more key
  /// (see [PqMultiRecipient]) — the payload is still sealed exactly once. On
  /// failure the partial [output] is removed.
  Future<PqStreamingStats> encryptFile({
    required Uint8List recipientPublicKey,
    required File input,
    required File output,
    required PqForgeProfile profile,
    Uint8List? recipientKexPublicKey,
    List<PqRecipientSpec> additionalRecipients = const [],
    String? recipientKeyId,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
    int frameSize = PqStreamingEnvelope.defaultFrameSize,
  }) async {
    final context = await _prepareEncrypt(
      recipientPublicKey: recipientPublicKey,
      recipientKexPublicKey: recipientKexPublicKey,
      additionalRecipients: additionalRecipients,
      recipientKeyId: recipientKeyId,
      profile: profile,
      aad: aad,
      metadata: metadata,
      signerSecretKey: signerSecretKey,
      signatureAlgorithm: signatureAlgorithm,
      signerKeyId: signerKeyId,
      frameSize: frameSize,
    );
    final source = await input.open();
    try {
      return await _writeContainer(context, output, (writer) async {
        final total = await source.length();
        if (total == 0) {
          // An empty input still gets one (empty) final frame so the reader
          // sees a terminator rather than a truncated stream.
          await writer.add(Uint8List(0), isFinal: true);
          return;
        }
        // Double-buffered read-ahead (R9): the next frame is read from the
        // source while the current one is sealed and written. Input and
        // output are separate file handles, so the disk read genuinely
        // overlaps the AEAD + write; peak memory grows by exactly one frame.
        var current = Uint8List(frameSize);
        var next = Uint8List(frameSize);
        var read = await source.readInto(current);
        var currentLen = read;
        while (currentLen > 0) {
          final isFinal = read >= total;
          final pending = isFinal ? null : source.readInto(next);
          try {
            await writer.add(
              Uint8List.sublistView(current, 0, currentLen),
              isFinal: isFinal,
            );
          } on Object {
            // Never leave the prefetch dangling: an unawaited failing future
            // would surface as an unhandled async error during cleanup.
            await _drainQuietly(pending);
            rethrow;
          }
          if (pending == null) return;
          final n = await pending;
          if (n <= 0) break; // input shrank; the reader detects truncation
          read += n;
          currentLen = n;
          final spare = current;
          current = next;
          next = spare;
        }
      });
    } finally {
      await source.close();
    }
  }

  /// Streams arbitrary plaintext [source] bytes into a `.pqfs` container at
  /// [output] — same container, framing, and signing as [encryptFile], but the
  /// input never has to exist as a file. This is what lets `pack` seal a whole
  /// folder without ever spooling plaintext to disk.
  ///
  /// The total length need not be known up front: a one-frame lookahead decides
  /// which frame is final. Peak memory ≈ 2 × [frameSize].
  Future<PqStreamingStats> encryptStream({
    required Uint8List recipientPublicKey,
    required Stream<List<int>> source,
    required File output,
    required PqForgeProfile profile,
    Uint8List? recipientKexPublicKey,
    List<PqRecipientSpec> additionalRecipients = const [],
    String? recipientKeyId,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
    int frameSize = PqStreamingEnvelope.defaultFrameSize,
  }) async {
    final context = await _prepareEncrypt(
      recipientPublicKey: recipientPublicKey,
      recipientKexPublicKey: recipientKexPublicKey,
      additionalRecipients: additionalRecipients,
      recipientKeyId: recipientKeyId,
      profile: profile,
      aad: aad,
      metadata: metadata,
      signerSecretKey: signerSecretKey,
      signatureAlgorithm: signatureAlgorithm,
      signerKeyId: signerKeyId,
      frameSize: frameSize,
    );
    return _writeContainer(context, output, (writer) async {
      // (No read-ahead here: the source is already an async stream, so the
      // producer naturally runs ahead while a frame is awaited.)
      final frame = Uint8List(frameSize);
      var filled = 0;
      Uint8List? readyFrame; // full frame held until finality is known
      await for (final chunk in source) {
        var offset = 0;
        while (offset < chunk.length) {
          final n = (frameSize - filled) < (chunk.length - offset)
              ? frameSize - filled
              : chunk.length - offset;
          frame.setRange(filled, filled + n, chunk, offset);
          filled += n;
          offset += n;
          if (filled == frameSize) {
            if (readyFrame != null) {
              await writer.add(readyFrame, isFinal: false);
            }
            readyFrame = Uint8List.fromList(frame);
            filled = 0;
          }
        }
      }
      if (readyFrame != null) {
        if (filled == 0) {
          await writer.add(readyFrame, isFinal: true);
        } else {
          await writer.add(readyFrame, isFinal: false);
          await writer.add(
            Uint8List.sublistView(frame, 0, filled),
            isFinal: true,
          );
        }
      } else {
        // Covers both a short (<1 frame) stream and a fully empty one.
        await writer.add(
          Uint8List.sublistView(frame, 0, filled),
          isFinal: true,
        );
      }
    });
  }

  /// KEM-encapsulates, derives the DEM key, and serializes + signs the header —
  /// the shared prologue of [encryptFile] and [encryptStream]. With a
  /// [recipientKexPublicKey] the DEM key is the hybrid combination and the
  /// header metadata carries the self-describing `hybridKex` marker; a
  /// non-default engine suite and any [additionalRecipients] key-wrap entries
  /// are recorded the same way.
  Future<_EncryptContext> _prepareEncrypt({
    required Uint8List recipientPublicKey,
    required Uint8List? recipientKexPublicKey,
    required List<PqRecipientSpec> additionalRecipients,
    required String? recipientKeyId,
    required PqForgeProfile profile,
    required Uint8List? aad,
    required Map<String, Object?> metadata,
    required Uint8List? signerSecretKey,
    required PqSignatureAlgorithm? signatureAlgorithm,
    required String? signerKeyId,
    required int frameSize,
  }) async {
    final signatureAlg = signerSecretKey == null
        ? signatureAlgorithm
        : (signatureAlgorithm ?? profile.signature);
    requireWritableEnvelopeMetadata(metadata);
    final encapsulated = PqKemPrimitives.encapsulate(
      profile.kem,
      recipientPublicKey,
    );
    final Uint8List demKey;
    var effectiveMetadata = {
      ...metadata,
      ...PqAeadSuite.entryFor(engine.cipherSuite),
    };
    if (recipientKexPublicKey == null) {
      demKey = PqForge.deriveDemKey(
        profile,
        encapsulated.sharedSecret,
        encapsulated.ciphertext,
      );
    } else {
      final hybrid = await PqHybridKemDem.encapsulate(
        profile: profile,
        kemSharedSecret: encapsulated.sharedSecret,
        kemCiphertext: encapsulated.ciphertext,
        recipientKexPublicKey: recipientKexPublicKey,
      );
      demKey = hybrid.demKey;
      effectiveMetadata = {...effectiveMetadata, ...hybrid.metadataEntry};
    }
    if (additionalRecipients.isNotEmpty) {
      effectiveMetadata = {
        ...effectiveMetadata,
        PqMultiRecipient.primaryKeyIdKey: ?recipientKeyId,
        PqMultiRecipient.metadataKey: await PqMultiRecipient.buildEntries(
          profile: profile,
          demKey: demKey,
          recipients: additionalRecipients,
        ),
      };
    }
    final header = PqStreamingHeader(
      profile: profile,
      kemAlgorithm: profile.kem,
      signatureAlgorithm: signatureAlg,
      kemCiphertext: encapsulated.ciphertext,
      nonceSalt: PqBytes.randomBytes(PqStreamingEnvelope.nonceSaltBytes),
      frameSize: frameSize,
      aadHash: aad == null ? null : PqBytes.sha256(aad),
      metadata: effectiveMetadata,
      signerKeyId: signerKeyId,
    );
    final headerCore = PqStreamingEnvelope.serializeHeaderCore(header);
    final signature = signerSecretKey == null
        ? Uint8List(0)
        : PqSignaturePrimitives.sign(
            signatureAlg!,
            signerSecretKey,
            headerCore,
            context: PqStreamingEnvelope.signatureContext(),
            preHash: true,
          );
    return _EncryptContext(
      demKey: demKey,
      nonceSalt: header.nonceSalt,
      headerCore: headerCore,
      headerHash: PqBytes.sha256(headerCore),
      signature: signature,
      signed: signerSecretKey != null,
    );
  }

  /// Opens [output], writes the container header, runs [body] with a
  /// [_FrameWriter], and returns the stats. Deletes the partial output if
  /// anything fails.
  Future<PqStreamingStats> _writeContainer(
    _EncryptContext context,
    File output,
    Future<void> Function(_FrameWriter writer) body,
  ) async {
    await output.parent.create(recursive: true);
    final sink = await output.open(mode: FileMode.write);
    var success = false;
    try {
      final containerHeader = _buildContainerHeader(
        context.headerCore,
        context.signature,
      );
      await sink.writeFrom(containerHeader);
      final writer = _FrameWriter(
        engine: engine,
        sink: sink,
        demKey: context.demKey,
        headerHash: context.headerHash,
        nonceSalt: context.nonceSalt,
      );
      await body(writer);
      await sink.flush();
      success = true;
      return PqStreamingStats(
        plaintextBytes: writer.plaintextBytes,
        containerBytes: containerHeader.length + writer.bytesWritten,
        frameCount: writer.frameCount,
        signed: context.signed,
      );
    } finally {
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
    Uint8List? recipientKexSecretKey,
    String? recipientKeyId,
    Uint8List? signerPublicKey,
    Uint8List? Function(PqStreamingHeader header)? aadResolver,
  }) async {
    await output.parent.create(recursive: true);
    final sink = await output.open(mode: FileMode.write);
    PqStreamingHeader? header;
    var success = false;
    try {
      final frames = decryptStream(
        recipientSecretKey: recipientSecretKey,
        recipientKexSecretKey: recipientKexSecretKey,
        recipientKeyId: recipientKeyId,
        input: input,
        signerPublicKey: signerPublicKey,
        aadResolver: aadResolver,
        onHeader: (h) => header = h,
      );
      await for (final plaintext in frames) {
        if (plaintext.isNotEmpty) await sink.writeFrom(plaintext);
      }
      await sink.flush();
      success = true;
      return header!;
    } finally {
      await sink.close();
      if (!success) await _deleteQuietly(output);
    }
  }

  /// Streams the authenticated plaintext of a `.pqfs` [input], one frame at a
  /// time, without materializing it anywhere — the consumer decides what to do
  /// with each frame (write it, parse it, forward it).
  ///
  /// Every frame is verified (tag + position + finality) **before** it is
  /// yielded, so a consumer only ever sees authentic bytes; truncation is
  /// detected at the end of the stream. [onHeader] fires once after the header
  /// (and its signature, when present) has been verified.
  ///
  /// Hybrid containers (those whose header metadata carries the `hybridKex`
  /// marker) require [recipientKexSecretKey] — the raw 32-byte X25519 secret
  /// matching the public key the sender encrypted to; a missing key fails
  /// before any frame is read **unless** the container also carries
  /// `recipients[]` entries, which are then still tried. The key is ignored
  /// for non-hybrid containers.
  ///
  /// Multi-recipient containers resolve the DEM key on the first frame: the
  /// primary derivation and the `recipients[]` unwrap are trial-opened and
  /// the authenticating one is kept. [recipientKeyId] (this key's id) routes
  /// straight to the matching wrap entry. A non-default AEAD suite recorded
  /// in the header (`aeadSuite`) rebuilds the engine on the same provider.
  Stream<Uint8List> decryptStream({
    required Uint8List recipientSecretKey,
    required File input,
    Uint8List? recipientKexSecretKey,
    String? recipientKeyId,
    Uint8List? signerPublicKey,
    Uint8List? Function(PqStreamingHeader header)? aadResolver,
    void Function(PqStreamingHeader header)? onHeader,
  }) async* {
    final source = await input.open();
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
      onHeader?.call(header);

      // The container records a non-default AEAD suite in its header
      // metadata; rebuild the engine on the same provider to match it.
      final suite = PqAeadSuite.of(header.metadata);
      PqFipsMode.requireApprovedSuite(suite);
      final aead = engine.cipherSuite == suite
          ? engine
          : aeadEngineForProvider(engine.provider, cipherSuite: suite);

      final sharedSecret = PqKemPrimitives.decapsulate(
        header.kemAlgorithm,
        recipientSecretKey,
        header.kemCiphertext,
      );
      final hasEntries = PqMultiRecipient.hasEntries(header.metadata);

      // Primary derivation. On a multi-recipient container its failure (e.g.
      // a hybrid primary but no kex key — we may not BE the primary) is
      // deferred so the recipients[] entries still get their chance.
      Uint8List? primaryDemKey;
      PqForgeException? primaryFailure;
      try {
        if (PqHybridKemDem.isHybrid(header.metadata)) {
          if (recipientKexSecretKey == null) {
            throw const PqForgeException(
              'This container uses hybrid ML-KEM + X25519 encryption; the '
              'recipient X25519 secret key is required to decrypt it',
            );
          }
          primaryDemKey = await PqHybridKemDem.demKeyForOpen(
            profile: header.profile,
            kemSharedSecret: sharedSecret,
            kemCiphertext: header.kemCiphertext,
            metadata: header.metadata,
            recipientKexSecretKey: recipientKexSecretKey,
          );
        } else {
          primaryDemKey = PqForge.deriveDemKey(
            header.profile,
            sharedSecret,
            header.kemCiphertext,
          );
        }
      } on PqForgeException catch (failure) {
        if (!hasEntries) rethrow;
        primaryFailure = failure;
      }

      // Candidate DEM keys, primary first unless the metadata names a
      // different primary key id than ours. With several candidates the one
      // that authenticates the first frame wins and is kept for the rest.
      final candidates = <Uint8List>[];
      if (!hasEntries) {
        candidates.add(primaryDemKey!);
      } else {
        final entriesKey = await PqMultiRecipient.unwrapDemKey(
          profile: header.profile,
          metadata: header.metadata,
          recipientSecretKey: recipientSecretKey,
          recipientKexSecretKey: recipientKexSecretKey,
          recipientKeyId: recipientKeyId,
        );
        final namedPrimary = header.metadata[PqMultiRecipient.primaryKeyIdKey];
        final preferEntries =
            recipientKeyId != null &&
            namedPrimary is String &&
            namedPrimary != recipientKeyId;
        for (final key
            in preferEntries
                ? [entriesKey, primaryDemKey]
                : [primaryDemKey, entriesKey]) {
          if (key != null) candidates.add(key);
        }
        if (candidates.isEmpty) {
          throw PqForgeException(
            'This multi-recipient container is not addressed to the supplied '
            'key: the primary derivation was unavailable '
            '(${primaryFailure?.message}) and no recipients[] entry unwrapped',
          );
        }
      }
      // Multi-recipient containers always resolve via the first-frame trial,
      // even with a single candidate, so a wrong key surfaces as the
      // descriptive "not addressed" error rather than a bare tag failure.
      var demKey = hasEntries ? null : candidates.single;

      final tagLength = aead.cipherSuite.tagLength;
      final maxBody = header.frameSize + tagLength;

      // One frame of read-ahead (R9): the next frame loads from disk while
      // the current one is opened. The observable validation order is
      // unchanged — a prefetched frame is only inspected after every earlier
      // frame has authenticated and been yielded.
      Future<({int seq, bool isFinal, Uint8List body})?> readFrame() async {
        final frameHeader = await _readExactlyOrNull(
          source,
          PqStreamingEnvelope.frameHeaderBytes,
        );
        if (frameHeader == null) return null; // clean EOF at a frame boundary
        final parsed = PqStreamingEnvelope.parseFrameHeader(frameHeader);
        // Bound the body length BEFORE allocating it (anti-DoS).
        if (parsed.bodyLen < tagLength || parsed.bodyLen > maxBody) {
          throw PqForgeException(
            'Invalid streaming frame body length: ${parsed.bodyLen}',
          );
        }
        return (
          seq: parsed.seq,
          isFinal: parsed.isFinal,
          body: await _readExactly(source, parsed.bodyLen),
        );
      }

      var expectedSeq = 0;
      var sawFinal = false;
      var current = await readFrame();
      while (current != null) {
        if (sawFinal) {
          throw const PqForgeException(
            'Trailing data after the final streaming frame',
          );
        }
        if (current.seq != expectedSeq) {
          throw PqForgeException(
            'Streaming frame out of order: expected $expectedSeq, '
            'got ${current.seq}',
          );
        }
        final pending = current.isFinal ? null : readFrame();
        Uint8List plaintext;
        try {
          if (demKey != null) {
            plaintext = await PqStreamingEnvelope.openFrameBody(
              engine: aead,
              demKey: demKey,
              headerHash: container.headerHash,
              nonceSalt: header.nonceSalt,
              seq: expectedSeq,
              isFinal: current.isFinal,
              body: current.body,
            );
          } else {
            // First frame of a multi-recipient container: trial-open the
            // candidates and keep the one that authenticates.
            Uint8List? opened;
            for (final candidate in candidates) {
              try {
                opened = await PqStreamingEnvelope.openFrameBody(
                  engine: aead,
                  demKey: candidate,
                  headerHash: container.headerHash,
                  nonceSalt: header.nonceSalt,
                  seq: expectedSeq,
                  isFinal: current.isFinal,
                  body: current.body,
                );
                demKey = candidate;
                break;
              } on PqForgeAuthTagException {
                continue;
              }
            }
            plaintext =
                opened ??
                (throw const PqForgeException(
                  'This multi-recipient container is not addressed to the '
                  'supplied key: no candidate DEM key authenticated',
                ));
          }
        } on Object {
          // Never leave the prefetch dangling: closing the source in the
          // finally below would fail it into an unawaited future.
          await _drainQuietly(pending);
          rethrow;
        }
        if (current.isFinal) sawFinal = true;
        expectedSeq++;
        yield plaintext;
        current = pending == null ? await readFrame() : await pending;
      }
      if (!sawFinal) {
        throw const PqForgeException(
          'Truncated streaming envelope: missing final frame',
        );
      }
    } finally {
      await source.close();
    }
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
    // Validate untrusted lengths BEFORE allocating: a malicious container can
    // claim up to 4 GiB here and would otherwise force the allocation attempt.
    final headerCoreLen = _readUint32(await _readExactly(source, 4));
    if (headerCoreLen <= 0 ||
        headerCoreLen > PqStreamingEnvelope.maxHeaderCoreBytes) {
      throw PqForgeException('Invalid streaming header length: $headerCoreLen');
    }
    final headerCore = await _readExactly(source, headerCoreLen);
    final signatureLen = _readUint32(await _readExactly(source, 4));
    final maxSignature = PqSignatureAlgorithm.values
        .map((algorithm) => algorithm.signatureBytes)
        .reduce((a, b) => a > b ? a : b);
    if (signatureLen > maxSignature) {
      throw PqForgeException(
        'Invalid streaming signature length: $signatureLen',
      );
    }
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

/// The per-container crypto state shared by the file and stream encrypt paths.
class _EncryptContext {
  _EncryptContext({
    required this.demKey,
    required this.nonceSalt,
    required this.headerCore,
    required this.headerHash,
    required this.signature,
    required this.signed,
  });

  final Uint8List demKey;
  final Uint8List nonceSalt;
  final Uint8List headerCore;
  final Uint8List headerHash;
  final Uint8List signature;
  final bool signed;
}

/// Seals plaintext frames in order and writes them to the container sink,
/// tracking the stats the public API reports.
class _FrameWriter {
  _FrameWriter({
    required this.engine,
    required this.sink,
    required this.demKey,
    required this.headerHash,
    required this.nonceSalt,
  });

  final PqForgeAeadEngine engine;
  final RandomAccessFile sink;
  final Uint8List demKey;
  final Uint8List headerHash;
  final Uint8List nonceSalt;

  int _seq = 0;
  int plaintextBytes = 0;
  int bytesWritten = 0;
  int get frameCount => _seq;

  Future<void> add(Uint8List plaintext, {required bool isFinal}) async {
    final body = await PqStreamingEnvelope.sealFrameBody(
      engine: engine,
      demKey: demKey,
      headerHash: headerHash,
      nonceSalt: nonceSalt,
      seq: _seq,
      isFinal: isFinal,
      plaintext: plaintext,
    );
    final frameHeader = PqStreamingEnvelope.buildFrameHeader(
      bodyLen: body.length,
      seq: _seq,
      isFinal: isFinal,
    );
    await sink.writeFrom(frameHeader);
    await sink.writeFrom(body);
    plaintextBytes += plaintext.length;
    bytesWritten += frameHeader.length + body.length;
    _seq++;
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

/// Awaits a possibly in-flight read-ahead, swallowing its error: the primary
/// failure is already propagating, and an unawaited failing future would
/// otherwise surface as an unhandled async error during cleanup.
Future<void> _drainQuietly(Future<Object?>? pending) async {
  if (pending == null) return;
  try {
    await pending;
  } catch (_) {
    // Deliberately ignored — see above.
  }
}
