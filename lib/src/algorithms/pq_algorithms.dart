/// Algorithm names, profiles, sizes, and validation rules for pqforge.
library;

import 'dart:typed_data';

const pqForgeEnvelopeMagic = 'PQF1';
const pqForgeEnvelopeVersion = 1;
const pqForgeInfoPrefix = 'pqcrypto universal-pqc-framework v1';
const pqForgeDefaultAeadNonceBytes = 12;
const pqForgeDefaultSessionKeyBytes = 32;
const pqForgeDefaultDeploymentSaltBytes = 32;

/// ML-KEM parameter sets supported by pqforge.
enum PqKemAlgorithm {
  mlKem512(
    id: 'ml-kem-512',
    name: 'ML-KEM-512',
    securityCategory: 1,
    publicKeyBytes: 800,
    secretKeyBytes: 1632,
    ciphertextBytes: 768,
  ),
  mlKem768(
    id: 'ml-kem-768',
    name: 'ML-KEM-768',
    securityCategory: 3,
    publicKeyBytes: 1184,
    secretKeyBytes: 2400,
    ciphertextBytes: 1088,
  ),
  mlKem1024(
    id: 'ml-kem-1024',
    name: 'ML-KEM-1024',
    securityCategory: 5,
    publicKeyBytes: 1568,
    secretKeyBytes: 3168,
    ciphertextBytes: 1568,
  );

  const PqKemAlgorithm({
    required this.id,
    required this.name,
    required this.securityCategory,
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.ciphertextBytes,
  });

  final String id;
  final String name;
  final int securityCategory;
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int ciphertextBytes;

  int get sharedSecretBytes => 32;

  static PqKemAlgorithm byId(String id) {
    for (final value in values) {
      if (value.id == id || value.name == id) return value;
    }
    throw PqForgeException('Unsupported ML-KEM algorithm: $id');
  }
}

/// ML-DSA parameter sets supported by pqforge.
enum PqSignatureAlgorithm {
  mlDsa44(
    id: 'ml-dsa-44',
    name: 'ML-DSA-44',
    securityCategory: 2,
    publicKeyBytes: 1312,
    secretKeyBytes: 2560,
    signatureBytes: 2420,
  ),
  mlDsa65(
    id: 'ml-dsa-65',
    name: 'ML-DSA-65',
    securityCategory: 3,
    publicKeyBytes: 1952,
    secretKeyBytes: 4032,
    signatureBytes: 3309,
  ),
  mlDsa87(
    id: 'ml-dsa-87',
    name: 'ML-DSA-87',
    securityCategory: 5,
    publicKeyBytes: 2592,
    secretKeyBytes: 4896,
    signatureBytes: 4627,
  );

  const PqSignatureAlgorithm({
    required this.id,
    required this.name,
    required this.securityCategory,
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.signatureBytes,
  });

  final String id;
  final String name;
  final int securityCategory;
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int signatureBytes;

  static PqSignatureAlgorithm byId(String id) {
    for (final value in values) {
      if (value.id == id || value.name == id) return value;
    }
    throw PqForgeException('Unsupported ML-DSA algorithm: $id');
  }
}

/// A named composition profile for common post-quantum choices.
class PqForgeProfile {
  const PqForgeProfile({
    required this.name,
    required this.kem,
    required this.signature,
    this.sessionKeyBytes = pqForgeDefaultSessionKeyBytes,
    this.infoPrefix = pqForgeInfoPrefix,
  });

  static const compact = PqForgeProfile(
    name: 'compact',
    kem: PqKemAlgorithm.mlKem512,
    signature: PqSignatureAlgorithm.mlDsa44,
  );

  static const balanced = PqForgeProfile(
    name: 'balanced',
    kem: PqKemAlgorithm.mlKem768,
    signature: PqSignatureAlgorithm.mlDsa65,
  );

  static const maximum = PqForgeProfile(
    name: 'maximum',
    kem: PqKemAlgorithm.mlKem1024,
    signature: PqSignatureAlgorithm.mlDsa87,
  );

  final String name;
  final PqKemAlgorithm kem;
  final PqSignatureAlgorithm signature;
  final int sessionKeyBytes;
  final String infoPrefix;

  static PqForgeProfile byName(String name) {
    return switch (name) {
      'compact' => compact,
      'balanced' => balanced,
      'maximum' => maximum,
      _ => throw PqForgeException('Unsupported pqforge profile: $name'),
    };
  }
}

class PqForgeException implements Exception {
  const PqForgeException(this.message);

  final String message;

  @override
  String toString() => 'PqForgeException: $message';
}

void requireLength(String name, Uint8List value, int expected) {
  if (value.length != expected) {
    throw ArgumentError.value(value.length, name, 'expected $expected bytes');
  }
}

void requireDsaContext(Uint8List? context) {
  if ((context?.length ?? 0) > 255) {
    throw ArgumentError.value(context!.length, 'context', 'max 255 bytes');
  }
}
