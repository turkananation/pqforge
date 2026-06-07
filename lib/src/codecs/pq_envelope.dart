/// Binary and JSON envelope formats for pqforge payloads.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
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
