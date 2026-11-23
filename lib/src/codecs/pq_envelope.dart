/// Binary and JSON envelope formats for pqforge payloads.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/src/exceptions/pqforge_exception.dart';

import '../algorithms/pq_algorithms.dart';
import '../primitives/pq_primitives.dart';

class PqEnvelope {
  PqEnvelope({
    this.version = pqForgeEnvelopeVersion,
    required this.profile,
    required this.kemAlgorithm,
    this.signatureAlgorithm,
    this.slhDsa,
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
    if (signatureAlgorithm != null && slhDsa != null) {
      throw const PqForgeException(
        'Pass only one of signatureAlgorithm or slhDsa',
      );
    }
    if (this.signature != null &&
        signatureAlgorithm == null &&
        slhDsa == null) {
      throw const PqForgeException(
        'signatureAlgorithm or slhDsa is required with signature',
      );
    }
    if (this.signature != null) {
      requireLength(
        'signature',
        this.signature!,
        slhDsa?.signatureBytes ?? signatureAlgorithm!.signatureBytes,
      );
    }
  }

  final int version;
  final PqForgeProfile profile;
  final PqKemAlgorithm kemAlgorithm;
  final PqSignatureAlgorithm? signatureAlgorithm;

  /// Set when the header signature is SLH-DSA. Mutually exclusive with
  /// [signatureAlgorithm]. HashSLH-DSA over the envelope digest, once.
  final PqSlhDsaAlgorithm? slhDsa;
  final Uint8List kemCiphertext;
  final Uint8List nonce;
  final Uint8List payload;
  final Uint8List? aadHash;
  final String? signerKeyId;
  final Uint8List? signature;
  final Map<String, Object?> metadata;

  bool get isSigned => signature != null;

  /// `ml-dsa-65` or `slh-dsa-shake-128f`, when a signature algorithm is set.
  String? get signatureAlgorithmId => slhDsa?.id ?? signatureAlgorithm?.id;

  /// Display name of [signatureAlgorithmId].
  String? get signatureAlgorithmName =>
      slhDsa?.name ?? signatureAlgorithm?.name;

  Uint8List toBinary() {
    final metadataJson = jsonEncode(metadata);
    return PqBytes.lengthPrefixed([
      PqBytes.utf8Bytes(pqForgeEnvelopeMagic),
      PqBytes.uint32(version),
      PqBytes.utf8Bytes(profile.name),
      PqBytes.utf8Bytes(kemAlgorithm.id),
      PqBytes.utf8Bytes(slhDsa?.id ?? signatureAlgorithm?.id ?? ''),
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
    final fields = PqBytes.decodeLengthPrefixed(data);
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
    final algorithms = splitHeaderSignatureId(sigId);
    final profile = PqForgeProfile.resolve(profileName, kem, algorithms.mlDsa);
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
      signatureAlgorithm: algorithms.mlDsa,
      slhDsa: algorithms.slhDsa,
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
    if (signatureAlgorithm != null || slhDsa != null)
      'signatureAlgorithm': slhDsa?.id ?? signatureAlgorithm!.id,
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
    final algorithms = splitHeaderSignatureId(sigId ?? '');
    final profile = PqForgeProfile.resolve(
      json['profile'] as String,
      kem,
      algorithms.mlDsa,
    );
    return PqEnvelope(
      version: json['version'] as int? ?? pqForgeEnvelopeVersion,
      profile: profile,
      kemAlgorithm: kem,
      signatureAlgorithm: algorithms.mlDsa,
      slhDsa: algorithms.slhDsa,
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

// The `.pqfs` streaming codec (PqStreamingHeader / PqStreamingEnvelope) lives
// in pq_streaming_envelope.dart. Its frame counters are encoded as two uint32
// halves, so the codec is dart2js-safe and ships in the same web-safe core
// umbrella as this file; only the dart:io stream cipher is pqforge_io-only.
