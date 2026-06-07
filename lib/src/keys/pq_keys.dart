/// Portable key containers and custody interfaces.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';

abstract final class PqKeyKind {
  static const kemPublic = 'kem-public';
  static const kemSecret = 'kem-secret';
  static const signaturePublic = 'signature-public';
  static const signatureSecret = 'signature-secret';
}

class PqKeyPair {
  PqKeyPair({required Uint8List publicKey, required Uint8List secretKey})
    : publicKey = _copy(publicKey),
      secretKey = _copy(secretKey);

  final Uint8List publicKey;
  final Uint8List secretKey;
}

class PqKeyBundle {
  PqKeyBundle({
    required this.profile,
    required this.kemKeyPair,
    required this.signatureKeyPair,
    this.keyId,
  });

  final PqForgeProfile profile;
  final PqKeyPair kemKeyPair;
  final PqKeyPair signatureKeyPair;
  final String? keyId;

  PqExportedKey exportKemPublicKey({String? keyId}) => PqExportedKey(
    kind: PqKeyKind.kemPublic,
    algorithmId: profile.kem.id,
    keyId: keyId ?? this.keyId,
    bytes: kemKeyPair.publicKey,
  );

  PqExportedKey exportKemSecretKey({String? keyId}) => PqExportedKey(
    kind: PqKeyKind.kemSecret,
    algorithmId: profile.kem.id,
    keyId: keyId ?? this.keyId,
    bytes: kemKeyPair.secretKey,
  );

  PqExportedKey exportSignaturePublicKey({String? keyId}) => PqExportedKey(
    kind: PqKeyKind.signaturePublic,
    algorithmId: profile.signature.id,
    keyId: keyId ?? this.keyId,
    bytes: signatureKeyPair.publicKey,
  );

  PqExportedKey exportSignatureSecretKey({String? keyId}) => PqExportedKey(
    kind: PqKeyKind.signatureSecret,
    algorithmId: profile.signature.id,
    keyId: keyId ?? this.keyId,
    bytes: signatureKeyPair.secretKey,
  );
}

class PqKemEncapsulation {
  PqKemEncapsulation({
    required this.algorithm,
    required Uint8List ciphertext,
    required Uint8List sharedSecret,
  }) : ciphertext = _copy(ciphertext),
       sharedSecret = _copy(sharedSecret);

  final PqKemAlgorithm algorithm;
  final Uint8List ciphertext;
  final Uint8List sharedSecret;
}

class PqExportedKey {
  PqExportedKey({
    required this.kind,
    required this.algorithmId,
    required Uint8List bytes,
    this.keyId,
  }) : bytes = _copy(bytes);

  final String kind;
  final String algorithmId;
  final Uint8List bytes;
  final String? keyId;

  Map<String, Object?> toJson() => {
    'kind': kind,
    'algorithmId': algorithmId,
    'bytes': base64Encode(bytes),
    if (keyId != null) 'keyId': keyId,
  };

  static PqExportedKey fromJson(Map<String, Object?> json) {
    return PqExportedKey(
      kind: json['kind'] as String,
      algorithmId: json['algorithmId'] as String,
      bytes: base64Decode(json['bytes'] as String),
      keyId: json['keyId'] as String?,
    );
  }
}

class PqWrappedKey {
  PqWrappedKey({
    required this.kdf,
    required this.aead,
    required Uint8List salt,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required this.keyKind,
    required this.algorithmId,
    this.keyId,
    this.iterations = 2,
    this.memoryPowerOf2 = 16,
    this.lanes = 4,
  }) : salt = _copy(salt),
       nonce = _copy(nonce),
       ciphertext = _copy(ciphertext);

  final String kdf;
  final String aead;
  final Uint8List salt;
  final Uint8List nonce;
  final Uint8List ciphertext;
  final String keyKind;
  final String algorithmId;
  final String? keyId;
  final int iterations;
  final int memoryPowerOf2;
  final int lanes;

  Map<String, Object?> toJson() => {
    'version': pqForgeEnvelopeVersion,
    'kdf': kdf,
    'aead': aead,
    'salt': base64Encode(salt),
    'nonce': base64Encode(nonce),
    'ciphertext': base64Encode(ciphertext),
    'keyKind': keyKind,
    'algorithmId': algorithmId,
    if (keyId != null) 'keyId': keyId,
    'iterations': iterations,
    'memoryPowerOf2': memoryPowerOf2,
    'lanes': lanes,
  };

  static PqWrappedKey fromJson(Map<String, Object?> json) {
    return PqWrappedKey(
      kdf: json['kdf'] as String,
      aead: json['aead'] as String,
      salt: base64Decode(json['salt'] as String),
      nonce: base64Decode(json['nonce'] as String),
      ciphertext: base64Decode(json['ciphertext'] as String),
      keyKind: json['keyKind'] as String,
      algorithmId: json['algorithmId'] as String,
      keyId: json['keyId'] as String?,
      iterations: json['iterations'] as int? ?? 2,
      memoryPowerOf2: json['memoryPowerOf2'] as int? ?? 16,
      lanes: json['lanes'] as int? ?? 4,
    );
  }
}

abstract interface class PqKeyStore {
  Future<void> put(String keyId, PqExportedKey key);
  Future<PqExportedKey?> get(String keyId);
  Future<void> delete(String keyId);
}

abstract interface class PqKeyResolver {
  Future<PqExportedKey?> resolvePublicKey(String keyId);
}

Uint8List _copy(Uint8List value) => Uint8List.fromList(value);
