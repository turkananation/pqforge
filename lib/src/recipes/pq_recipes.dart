/// Cookbook-backed recipe containers and canonical messages.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../primitives/pq_primitives.dart';

class PqIdentityBinding {
  PqIdentityBinding({
    required this.subjectId,
    required Uint8List identityPublicKey,
    required this.notBeforeMs,
    required this.expiresAtMs,
    required this.signatureAlgorithm,
    required Uint8List authoritySignature,
  }) : identityPublicKey = PqBytes.copy(identityPublicKey),
       authoritySignature = PqBytes.copy(authoritySignature);

  final String subjectId;
  final Uint8List identityPublicKey;
  final int notBeforeMs;
  final int expiresAtMs;
  final PqSignatureAlgorithm signatureAlgorithm;
  final Uint8List authoritySignature;

  Uint8List message() => PqRecipeMessages.identityBinding(
    subjectId: subjectId,
    identityPublicKey: identityPublicKey,
    notBeforeMs: notBeforeMs,
    expiresAtMs: expiresAtMs,
  );
}

class PqSignedLogEntry {
  PqSignedLogEntry({
    required Uint8List previousHash,
    required Uint8List payload,
    required this.timestampMs,
    required this.signatureAlgorithm,
    required Uint8List signature,
  }) : previousHash = PqBytes.copy(previousHash),
       payload = PqBytes.copy(payload),
       signature = PqBytes.copy(signature) {
    requireLength('previousHash', this.previousHash, 32);
    requireLength(
      'signature',
      this.signature,
      signatureAlgorithm.signatureBytes,
    );
  }

  final Uint8List previousHash;
  final Uint8List payload;
  final int timestampMs;
  final PqSignatureAlgorithm signatureAlgorithm;
  final Uint8List signature;

  Uint8List message() => PqRecipeMessages.logEntry(
    previousHash: previousHash,
    payload: payload,
    timestampMs: timestampMs,
  );

  Uint8List entryHash() =>
      PqBytes.sha256(PqBytes.concat([message(), signature]));
}

class PqArtifactSignature {
  PqArtifactSignature({
    required this.artifactId,
    required this.version,
    required Uint8List artifactHash,
    required this.signatureAlgorithm,
    required Uint8List signature,
  }) : artifactHash = PqBytes.copy(artifactHash),
       signature = PqBytes.copy(signature) {
    requireLength('artifactHash', this.artifactHash, 32);
    requireLength(
      'signature',
      this.signature,
      signatureAlgorithm.signatureBytes,
    );
  }

  final String artifactId;
  final int version;
  final Uint8List artifactHash;
  final PqSignatureAlgorithm signatureAlgorithm;
  final Uint8List signature;

  Uint8List message() => PqRecipeMessages.artifact(
    artifactId: artifactId,
    version: version,
    artifactHash: artifactHash,
  );
}

class PqSignedToken {
  PqSignedToken({
    required this.issuer,
    required this.subject,
    required this.issuedAtMs,
    required this.expiresAtMs,
    required Map<String, Object?> claims,
    required this.signatureAlgorithm,
    required Uint8List signature,
  }) : claims = Map.unmodifiable(claims),
       signature = PqBytes.copy(signature) {
    if (expiresAtMs <= issuedAtMs) {
      throw ArgumentError.value(
        expiresAtMs,
        'expiresAtMs',
        'must be greater than issuedAtMs',
      );
    }
    requireLength(
      'signature',
      this.signature,
      signatureAlgorithm.signatureBytes,
    );
  }

  final String issuer;
  final String subject;
  final int issuedAtMs;
  final int expiresAtMs;
  final Map<String, Object?> claims;
  final PqSignatureAlgorithm signatureAlgorithm;
  final Uint8List signature;

  Uint8List message() => PqRecipeMessages.token(
    issuer: issuer,
    subject: subject,
    issuedAtMs: issuedAtMs,
    expiresAtMs: expiresAtMs,
    claims: claims,
  );

  Map<String, Object?> toJson() => {
    'version': 1,
    'issuer': issuer,
    'subject': subject,
    'issuedAtMs': issuedAtMs,
    'expiresAtMs': expiresAtMs,
    'claims': claims,
    'signatureAlgorithm': signatureAlgorithm.id,
    'signature': base64Encode(signature),
  };

  static PqSignedToken fromJson(Map<String, Object?> json) {
    final version = json['version'] as int? ?? 1;
    if (version != 1) {
      throw PqForgeException('Unsupported signed token version: $version');
    }
    return PqSignedToken(
      issuer: json['issuer'] as String,
      subject: json['subject'] as String,
      issuedAtMs: json['issuedAtMs'] as int,
      expiresAtMs: json['expiresAtMs'] as int,
      claims: Map<String, Object?>.from(json['claims'] as Map? ?? const {}),
      signatureAlgorithm: PqSignatureAlgorithm.byId(
        json['signatureAlgorithm'] as String,
      ),
      signature: base64Decode(json['signature'] as String),
    );
  }
}

enum PqDualSignaturePolicy { requireBoth, acceptEither }

class PqDualSignature {
  PqDualSignature({
    required Uint8List pqcSignature,
    required Uint8List classicalSignature,
    this.policy = PqDualSignaturePolicy.requireBoth,
  }) : pqcSignature = PqBytes.copy(pqcSignature),
       classicalSignature = PqBytes.copy(classicalSignature);

  final Uint8List pqcSignature;
  final Uint8List classicalSignature;
  final PqDualSignaturePolicy policy;

  bool combine(bool pqcValid, bool classicalValid) {
    return switch (policy) {
      PqDualSignaturePolicy.requireBoth => pqcValid && classicalValid,
      PqDualSignaturePolicy.acceptEither => pqcValid || classicalValid,
    };
  }
}

class PqOffloadRequest {
  const PqOffloadRequest({
    required this.operation,
    required this.profileName,
    this.payload = const [],
    this.metadata = const {},
  });

  final String operation;
  final String profileName;
  final List<int> payload;
  final Map<String, Object?> metadata;
}

class PqOffloadResponse {
  const PqOffloadResponse({
    required this.operation,
    required this.payload,
    this.metadata = const {},
  });

  final String operation;
  final List<int> payload;
  final Map<String, Object?> metadata;
}

class PqRecipeMessages {
  const PqRecipeMessages._();

  static Uint8List domain(String value) => PqBytes.utf8Bytes(value);

  static Uint8List identityBinding({
    required String subjectId,
    required Uint8List identityPublicKey,
    required int notBeforeMs,
    required int expiresAtMs,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/identity-binding/v1'),
      PqBytes.utf8Bytes(subjectId),
      identityPublicKey,
      PqBytes.uint64(notBeforeMs),
      PqBytes.uint64(expiresAtMs),
    ]);
  }

  static Uint8List logEntry({
    required Uint8List previousHash,
    required Uint8List payload,
    required int timestampMs,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/signed-log/v1'),
      previousHash,
      payload,
      PqBytes.uint64(timestampMs),
    ]);
  }

  static Uint8List artifact({
    required String artifactId,
    required int version,
    required Uint8List artifactHash,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/artifact-signature/v1'),
      PqBytes.utf8Bytes(artifactId),
      PqBytes.uint64(version),
      artifactHash,
    ]);
  }

  static Uint8List record({
    required String recordType,
    required String recordId,
    required Uint8List payload,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/record/v1'),
      PqBytes.utf8Bytes(recordType),
      PqBytes.utf8Bytes(recordId),
      payload,
    ]);
  }

  static Uint8List document({
    required String documentId,
    required Uint8List documentBytes,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/document/v1'),
      PqBytes.utf8Bytes(documentId),
      PqBytes.sha256(documentBytes),
      PqBytes.uint64(documentBytes.length),
    ]);
  }

  static Uint8List text({
    required String textId,
    required String encoding,
    required Uint8List textBytes,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/text/v1'),
      PqBytes.utf8Bytes(textId),
      PqBytes.utf8Bytes(encoding),
      PqBytes.sha256(textBytes),
      PqBytes.uint64(textBytes.length),
    ]);
  }

  static Uint8List media({
    required String mediaId,
    required String mimeType,
    required Uint8List mediaBytes,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/media/v1'),
      PqBytes.utf8Bytes(mediaId),
      PqBytes.utf8Bytes(mimeType),
      PqBytes.sha256(mediaBytes),
      PqBytes.uint64(mediaBytes.length),
    ]);
  }

  static Uint8List webhook({
    required String eventType,
    required int timestampMs,
    required Uint8List payload,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/webhook/v1'),
      PqBytes.utf8Bytes(eventType),
      PqBytes.uint64(timestampMs),
      PqBytes.sha256(payload),
    ]);
  }

  static Uint8List fileAad({
    required String fileName,
    String? relativePath,
    Uint8List? aad,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/file/v1'),
      PqBytes.utf8Bytes(fileName),
      PqBytes.utf8Bytes(relativePath ?? ''),
      aad ?? Uint8List(0),
    ]);
  }

  static Uint8List folderEntryAad({
    required String relativePath,
    Uint8List? aad,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/folder-entry/v1'),
      PqBytes.utf8Bytes(relativePath),
      aad ?? Uint8List(0),
    ]);
  }

  static Uint8List folderPackAad({Uint8List? aad}) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/folder-pack/v1'),
      aad ?? Uint8List(0),
    ]);
  }

  static Uint8List emailAad({required String messageId, Uint8List? aad}) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/email-seal/v1'),
      PqBytes.utf8Bytes(messageId),
      aad ?? Uint8List(0),
    ]);
  }

  static Uint8List textAad({required String textId, Uint8List? aad}) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/text-seal/v1'),
      PqBytes.utf8Bytes(textId),
      aad ?? Uint8List(0),
    ]);
  }

  static Uint8List mediaAad({
    required String mediaId,
    required String mimeType,
    Uint8List? aad,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/media-seal/v1'),
      PqBytes.utf8Bytes(mediaId),
      PqBytes.utf8Bytes(mimeType),
      aad ?? Uint8List(0),
    ]);
  }

  static Uint8List token({
    required String issuer,
    required String subject,
    required int issuedAtMs,
    required int expiresAtMs,
    required Map<String, Object?> claims,
  }) {
    return PqBytes.lengthPrefixed([
      domain('pqforge/signed-token/v1'),
      PqBytes.utf8Bytes(issuer),
      PqBytes.utf8Bytes(subject),
      PqBytes.uint64(issuedAtMs),
      PqBytes.uint64(expiresAtMs),
      PqBytes.utf8Bytes(_canonicalJson(claims)),
    ]);
  }

  static Uint8List metadata(Map<String, Object?> metadata) {
    return PqBytes.utf8Bytes(jsonEncode(metadata));
  }
}

String _canonicalJson(Object? value) => jsonEncode(_canonicalize(value));

Object? _canonicalize(Object? value) {
  if (value is Map) {
    final out = <String, Object?>{};
    final keys = value.keys.map((key) => key.toString()).toList()..sort();
    for (final key in keys) {
      out[key] = _canonicalize(value[key]);
    }
    return out;
  }
  if (value is Iterable) {
    return value.map(_canonicalize).toList();
  }
  return value;
}
