/// Binary and JSON envelope formats for pqforge payloads.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../cipher/pq_cipher_suite.dart';
import '../primitives/pq_primitives.dart';

class PqEnvelope {
  PqEnvelope({
    this.version = pqForgeEnvelopeVersion,
    required this.profile,
    required this.kemAlgorithm,
    this.signatureAlgorithm,
    required Uint8List kemCiphertext,
    required Uint8List nonce,
    required Uint8List payload,
    Uint8List? aadHash,
    this.signerKeyId,
    Uint8List? signature,
    Map<String, Object?>? metadata,
  }) : kemCiphertext = PqBytes.copy(kemCiphertext),
       nonce = PqBytes.copy(nonce),
       payload = PqBytes.copy(payload),
       aadHash = aadHash == null ? null : PqBytes.copy(aadHash),
       signature = signature == null ? null : PqBytes.copy(signature),
       metadata = Map.unmodifiable(metadata ?? const {}) {
    if (version != pqForgeEnvelopeVersion) {
      throw PqForgeException('Unsupported envelope version: $version');
    }
    requireLength(
      'kemCiphertext',
      this.kemCiphertext,
      kemAlgorithm.ciphertextBytes,
    );
    requireLength('nonce', this.nonce, pqForgeDefaultAeadNonceBytes);
    if (this.aadHash != null) requireLength('aadHash', this.aadHash!, 32);
    if (this.signature != null && signatureAlgorithm == null) {
      throw const PqForgeException(
        'signatureAlgorithm is required with signature',
      );
    }
    if (this.signature != null) {
      requireLength(
        'signature',
        this.signature!,
        signatureAlgorithm!.signatureBytes,
      );
    }
  }

  final int version;
  final PqForgeProfile profile;
  final PqKemAlgorithm kemAlgorithm;
  final PqSignatureAlgorithm? signatureAlgorithm;
  final Uint8List kemCiphertext;
  final Uint8List nonce;
  final Uint8List payload;
  final Uint8List? aadHash;
  final String? signerKeyId;
  final Uint8List? signature;
  final Map<String, Object?> metadata;

  bool get isSigned => signature != null;

  Uint8List toBinary() {
    final metadataJson = jsonEncode(metadata);
    return PqBytes.lengthPrefixed([
      PqBytes.utf8Bytes(pqForgeEnvelopeMagic),
      PqBytes.uint32(version),
      PqBytes.utf8Bytes(profile.name),
      PqBytes.utf8Bytes(kemAlgorithm.id),
      PqBytes.utf8Bytes(signatureAlgorithm?.id ?? ''),
      nonce,
      kemCiphertext,
      payload,
      aadHash ?? Uint8List(0),
      PqBytes.utf8Bytes(signerKeyId ?? ''),
      signature ?? Uint8List(0),
      PqBytes.utf8Bytes(metadataJson),
    ]);
  }

  static PqEnvelope fromBinary(Uint8List data) {
    final fields = _decodeLengthPrefixed(data);
    if (fields.length != 12) {
      throw PqForgeException('Invalid envelope field count: ${fields.length}');
    }
    final magic = utf8.decode(fields[0]);
    if (magic != pqForgeEnvelopeMagic) {
      throw PqForgeException('Invalid envelope magic: $magic');
    }
    final version = fields[1].buffer
        .asByteData(fields[1].offsetInBytes, fields[1].lengthInBytes)
        .getUint32(0, Endian.big);
    final profileName = utf8.decode(fields[2]);
    final kem = PqKemAlgorithm.byId(utf8.decode(fields[3]));
    final sigId = utf8.decode(fields[4]);
    final sigAlg = sigId.isEmpty ? null : PqSignatureAlgorithm.byId(sigId);
    final profile = _profileByName(profileName, kem, sigAlg);
    final aadHash = fields[8].isEmpty ? null : fields[8];
    final signerKeyIdText = utf8.decode(fields[9]);
    final signerKeyId = signerKeyIdText.isEmpty ? null : signerKeyIdText;
    final signature = fields[10].isEmpty ? null : fields[10];
    final metadata = Map<String, Object?>.from(
      jsonDecode(utf8.decode(fields[11])) as Map,
    );

    return PqEnvelope(
      version: version,
      profile: profile,
      kemAlgorithm: kem,
      signatureAlgorithm: sigAlg,
      nonce: fields[5],
      kemCiphertext: fields[6],
      payload: fields[7],
      aadHash: aadHash,
      signerKeyId: signerKeyId,
      signature: signature,
      metadata: metadata,
    );
  }

  Map<String, Object?> toJson() => {
    'magic': pqForgeEnvelopeMagic,
    'version': version,
    'profile': profile.name,
    'kemAlgorithm': kemAlgorithm.id,
    if (signatureAlgorithm != null)
      'signatureAlgorithm': signatureAlgorithm!.id,
    'nonce': base64Encode(nonce),
    'kemCiphertext': base64Encode(kemCiphertext),
    'payload': base64Encode(payload),
    if (aadHash != null) 'aadHash': base64Encode(aadHash!),
    if (signerKeyId != null) 'signerKeyId': signerKeyId,
    if (signature != null) 'signature': base64Encode(signature!),
    if (metadata.isNotEmpty) 'metadata': metadata,
  };

  static PqEnvelope fromJson(Map<String, Object?> json) {
    final magic = json['magic'] as String?;
    if (magic != pqForgeEnvelopeMagic) {
      throw PqForgeException('Invalid envelope magic: $magic');
    }
    final sigId = json['signatureAlgorithm'] as String?;
    final kem = PqKemAlgorithm.byId(json['kemAlgorithm'] as String);
    final sigAlg = sigId == null ? null : PqSignatureAlgorithm.byId(sigId);
    final profile = _profileByName(json['profile'] as String, kem, sigAlg);
    return PqEnvelope(
      version: json['version'] as int? ?? pqForgeEnvelopeVersion,
      profile: profile,
      kemAlgorithm: kem,
      signatureAlgorithm: sigAlg,
      nonce: base64Decode(json['nonce'] as String),
      kemCiphertext: base64Decode(json['kemCiphertext'] as String),
      payload: base64Decode(json['payload'] as String),
      aadHash: json['aadHash'] == null
          ? null
          : base64Decode(json['aadHash'] as String),
      signerKeyId: json['signerKeyId'] as String?,
      signature: json['signature'] == null
          ? null
          : base64Decode(json['signature'] as String),
      metadata: json['metadata'] == null
          ? const {}
          : Map<String, Object?>.from(json['metadata'] as Map),
    );
  }
}

PqForgeProfile _profileByName(
  String name,
  PqKemAlgorithm kem,
  PqSignatureAlgorithm? signature,
) {
  try {
    return PqForgeProfile.byName(name);
  } on PqForgeException {
    return PqForgeProfile(
      name: name,
      kem: kem,
      signature: signature ?? PqSignatureAlgorithm.mlDsa65,
    );
  }
}

List<Uint8List> _decodeLengthPrefixed(Uint8List data) {
  final fields = <Uint8List>[];
  var offset = 0;
  while (offset < data.length) {
    if (offset + 4 > data.length) {
      throw const PqForgeException('Truncated envelope field length');
    }
    final length = data.buffer
        .asByteData(data.offsetInBytes + offset, 4)
        .getUint32(0, Endian.big);
    offset += 4;
    if (offset + length > data.length) {
      throw const PqForgeException('Truncated envelope field body');
    }
    fields.add(Uint8List.sublistView(data, offset, offset + length));
    offset += length;
  }
  return fields;
}

int _readUint32(Uint8List bytes) {
  if (bytes.length != 4) {
    throw const PqForgeException('Expected a 4-byte uint32 field');
  }
  return bytes.buffer
      .asByteData(bytes.offsetInBytes, 4)
      .getUint32(0, Endian.big);
}

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
    requireLength('nonceSalt', this.nonceSalt, PqStreamingEnvelope.nonceSaltBytes);
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

/// Pure, web-safe framing for the `.pqfs` streaming envelope.
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
      final fields = _decodeLengthPrefixed(bytes);
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
        profile: _profileByName(utf8.decode(fields[0]), kem, sig),
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
  static Uint8List frameNonce(Uint8List nonceSalt, int seq) {
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
    final view = header.buffer.asByteData(header.offsetInBytes, frameHeaderBytes);
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
