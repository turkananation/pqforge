/// Pure framing codec for the `.pqfs` streaming envelope.
///
/// This file is exported from `package:pqforge/pqforge_io.dart` (alongside the
/// `dart:io` stream cipher that drives it) rather than the core web-safe
/// umbrella: the frame counter uses `ByteData.setUint64`, which `dart2js` does
/// not support (VM and WASM are fine). Keeping it out of the core entrypoint
/// keeps `package:pqforge/pqforge.dart` importable-and-callable everywhere.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../cipher/pq_cipher_suite.dart';
import '../primitives/pq_primitives.dart';

/// The fixed, canonical, signed part of a `.pqfs` streaming-envelope header.
///
/// It carries everything a reader needs to derive the DEM key and authenticate
/// the frames, but never the payload. Serializing/parsing it is pure (no
/// `dart:io`); the file plumbing lives in the streaming I/O service.
class PqStreamingHeader {
  PqStreamingHeader({
    required this.profile,
    required this.kemAlgorithm,
    this.signatureAlgorithm,
    required Uint8List kemCiphertext,
    required Uint8List nonceSalt,
    required this.frameSize,
    Uint8List? aadHash,
    Map<String, Object?>? metadata,
    this.signerKeyId,
  }) : kemCiphertext = PqBytes.copy(kemCiphertext),
       nonceSalt = PqBytes.copy(nonceSalt),
       aadHash = aadHash == null ? null : PqBytes.copy(aadHash),
       metadata = Map.unmodifiable(metadata ?? const {}) {
    requireLength(
      'kemCiphertext',
      this.kemCiphertext,
      kemAlgorithm.ciphertextBytes,
    );
    requireLength(
      'nonceSalt',
      this.nonceSalt,
      PqStreamingEnvelope.nonceSaltBytes,
    );
    if (this.aadHash != null) requireLength('aadHash', this.aadHash!, 32);
    if (frameSize <= 0 || frameSize > PqStreamingEnvelope.maxFrameSize) {
      throw ArgumentError.value(
        frameSize,
        'frameSize',
        'must be in 1..${PqStreamingEnvelope.maxFrameSize}',
      );
    }
  }

  final PqForgeProfile profile;
  final PqKemAlgorithm kemAlgorithm;
  final PqSignatureAlgorithm? signatureAlgorithm;
  final Uint8List kemCiphertext;
  final Uint8List nonceSalt;
  final int frameSize;
  final Uint8List? aadHash;
  final Map<String, Object?> metadata;
  final String? signerKeyId;

  bool get isSigned => signatureAlgorithm != null;
}

/// Pure framing for the `.pqfs` streaming envelope.
///
/// Everything security-relevant — header serialization, per-frame nonce and AAD
/// derivation, and the AEAD seal/open of a single frame — lives here and is
/// unit-testable without touching the filesystem. The sequential file/stream
/// plumbing (and the KEM, signing, and AAD policy) lives in the `dart:io`
/// streaming service.
///
/// ## Container layout
///
/// ```text
/// "PQFS" | uint32 formatVersion
///        | uint32 headerCoreLen | headerCore
///        | uint32 signatureLen  | signature        (signatureLen 0 = unsigned)
///        | frame*
/// frame  = uint32 bodyLen | uint64 seq | uint8 isFinal | body(ciphertext‖tag)
/// ```
///
/// * `nonce = nonceSalt(4B) ‖ uint64(seq)` — unique under the per-file DEM key.
/// * `aad   = SHA-256(headerCore) ‖ uint64(seq) ‖ uint8(isFinal)` — binds every
///   frame to the header and makes truncation, reordering, duplication, and
///   splicing forgery-proof.
abstract final class PqStreamingEnvelope {
  /// Container magic; also distinguishes a streaming file from a one-shot
  /// envelope (whose `toBinary()` begins with the bytes `00 00 00 04`).
  static const magic = 'PQFS';

  /// Container format version.
  static const formatVersion = 1;

  /// Default frame size (1 MiB) — the resident working set is a small multiple
  /// of this, independent of total file length.
  static const defaultFrameSize = 1 << 20;

  /// Hard cap on a frame's plaintext size, enforced on read so a malicious
  /// header/frame can never force an unbounded allocation.
  static const maxFrameSize = 64 << 20;

  /// Hard cap on the serialized header (KEM ciphertext + metadata JSON),
  /// enforced on read before allocating — the same anti-DoS bound as
  /// [maxFrameSize] but for the container header.
  static const maxHeaderCoreBytes = 1 << 20;

  /// Maximum frames per container: the NIST SP 800-38D guidance of at most
  /// 2³² GCM invocations under one key. At the default 1 MiB frame size this
  /// caps a single container at 4 PiB.
  static const maxFrameCount = 1 << 32;

  /// Random per-file nonce-salt length, prefixed to the frame counter.
  static const nonceSaltBytes = 4;

  /// `uint32 bodyLen + uint64 seq + uint8 isFinal`.
  static const frameHeaderBytes = 4 + 8 + 1;

  /// Domain-separation context for the (optional) header signature.
  static Uint8List signatureContext() =>
      PqBytes.utf8Bytes('pqforge/streaming-envelope/v1');

  /// Serializes [header] to its canonical, signed `headerCore` bytes.
  static Uint8List serializeHeaderCore(PqStreamingHeader header) {
    return PqBytes.lengthPrefixed([
      PqBytes.utf8Bytes(header.profile.name),
      PqBytes.utf8Bytes(header.kemAlgorithm.id),
      PqBytes.utf8Bytes(header.signatureAlgorithm?.id ?? ''),
      header.kemCiphertext,
      header.nonceSalt,
      PqBytes.uint32(header.frameSize),
      header.aadHash ?? Uint8List(0),
      PqBytes.utf8Bytes(jsonEncode(header.metadata)),
      PqBytes.utf8Bytes(header.signerKeyId ?? ''),
    ]);
  }

  /// Parses canonical `headerCore` bytes back into a [PqStreamingHeader].
  ///
  /// Any structural defect in untrusted input (bad UTF-8, malformed JSON, wrong
  /// field count or lengths) surfaces as a [PqForgeException] rather than a raw
  /// `dart:convert`/`ArgumentError`, so callers can handle corruption uniformly.
  static PqStreamingHeader parseHeaderCore(Uint8List bytes) {
    try {
      final fields = PqBytes.decodeLengthPrefixed(bytes);
      if (fields.length != 9) {
        throw PqForgeException(
          'Invalid streaming header field count: ${fields.length}',
        );
      }
      final kem = PqKemAlgorithm.byId(utf8.decode(fields[1]));
      final sigId = utf8.decode(fields[2]);
      final sig = sigId.isEmpty ? null : PqSignatureAlgorithm.byId(sigId);
      final signerKeyIdText = utf8.decode(fields[8]);
      return PqStreamingHeader(
        profile: PqForgeProfile.resolve(utf8.decode(fields[0]), kem, sig),
        kemAlgorithm: kem,
        signatureAlgorithm: sig,
        kemCiphertext: fields[3],
        nonceSalt: fields[4],
        frameSize: _readUint32(fields[5]),
        aadHash: fields[6].isEmpty ? null : fields[6],
        metadata: Map<String, Object?>.from(
          jsonDecode(utf8.decode(fields[7])) as Map,
        ),
        signerKeyId: signerKeyIdText.isEmpty ? null : signerKeyIdText,
      );
    } on PqForgeException {
      rethrow;
    } catch (error) {
      throw PqForgeException('Malformed streaming envelope header: $error');
    }
  }

  /// `nonceSalt ‖ uint64(seq)` — a 12-byte AEAD nonce, unique per frame under
  /// the per-file DEM key.
  ///
  /// [seq] is bounded to [maxFrameCount] invocations per key (NIST SP 800-38D);
  /// enforcing it here covers both the writer and the reader, since every
  /// seal/open derives its nonce through this method.
  static Uint8List frameNonce(Uint8List nonceSalt, int seq) {
    if (seq < 0 || seq >= maxFrameCount) {
      throw PqForgeException(
        'Streaming frame count exceeds the per-key AES-GCM limit '
        '($maxFrameCount frames)',
      );
    }
    final nonce = Uint8List(pqForgeDefaultAeadNonceBytes)
      ..setRange(0, nonceSaltBytes, nonceSalt);
    nonce.buffer.asByteData().setUint64(nonceSaltBytes, seq, Endian.big);
    return nonce;
  }

  /// `SHA-256(headerCore) ‖ uint64(seq) ‖ uint8(isFinal)`.
  static Uint8List frameAad(Uint8List headerHash, int seq, bool isFinal) {
    final aad = Uint8List(headerHash.length + 9)
      ..setRange(0, headerHash.length, headerHash);
    aad.buffer.asByteData().setUint64(headerHash.length, seq, Endian.big);
    aad[headerHash.length + 8] = isFinal ? 1 : 0;
    return aad;
  }

  /// Builds a frame's `bodyLen | seq | isFinal` header.
  static Uint8List buildFrameHeader({
    required int bodyLen,
    required int seq,
    required bool isFinal,
  }) {
    final header = Uint8List(frameHeaderBytes);
    header.buffer.asByteData()
      ..setUint32(0, bodyLen, Endian.big)
      ..setUint64(4, seq, Endian.big);
    header[12] = isFinal ? 1 : 0;
    return header;
  }

  /// Parses a frame's `bodyLen | seq | isFinal` header.
  static ({int bodyLen, int seq, bool isFinal}) parseFrameHeader(
    Uint8List header,
  ) {
    if (header.length < frameHeaderBytes) {
      throw const PqForgeException('Truncated streaming frame header');
    }
    final view = header.buffer.asByteData(
      header.offsetInBytes,
      frameHeaderBytes,
    );
    return (
      bodyLen: view.getUint32(0, Endian.big),
      seq: view.getUint64(4, Endian.big),
      isFinal: header[12] != 0,
    );
  }

  /// Seals one plaintext frame, returning its `ciphertext‖tag` body.
  static Future<Uint8List> sealFrameBody({
    required PqForgeAeadEngine engine,
    required Uint8List demKey,
    required Uint8List headerHash,
    required Uint8List nonceSalt,
    required int seq,
    required bool isFinal,
    required Uint8List plaintext,
  }) {
    return engine.seal(
      key: demKey,
      nonce: frameNonce(nonceSalt, seq),
      plaintext: plaintext,
      aad: frameAad(headerHash, seq, isFinal),
    );
  }

  /// Opens one frame body back to plaintext, authenticating its position.
  static Future<Uint8List> openFrameBody({
    required PqForgeAeadEngine engine,
    required Uint8List demKey,
    required Uint8List headerHash,
    required Uint8List nonceSalt,
    required int seq,
    required bool isFinal,
    required Uint8List body,
  }) {
    return engine.open(
      key: demKey,
      nonce: frameNonce(nonceSalt, seq),
      cipherTextWithTag: body,
      aad: frameAad(headerHash, seq, isFinal),
    );
  }
}

int _readUint32(Uint8List bytes) {
  if (bytes.length != 4) {
    throw const PqForgeException('Expected a 4-byte uint32 field');
  }
  return bytes.buffer
      .asByteData(bytes.offsetInBytes, 4)
      .getUint32(0, Endian.big);
}
