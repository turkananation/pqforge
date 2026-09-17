/// Algorithm names, profiles, sizes, and validation rules for pqforge.
library;

import 'dart:typed_data';

import 'package:pqforge/src/exceptions/pqforge_exception.dart';

const pqForgeEnvelopeMagic = 'PQF1';

/// Envelope format version. Signatures are computed over a pre-hashed digest —
/// `SHA-256(headerFields ‖ SHA-256(payload))` signed with `preHash:true` — so
/// signing cost and memory are independent of payload size (defect M1). The
/// library is pre-release, so there is no prior wire format to interoperate
/// with.
const pqForgeEnvelopeVersion = 1;
const pqForgeInfoPrefix = 'pqcrypto universal-pqc-framework v1';
const pqForgeDefaultAeadNonceBytes = 12;
const pqForgeDefaultSessionKeyBytes = 32;
const pqForgeDefaultDeploymentSaltBytes = 32;

/// Metadata key whose presence marks an envelope/container as hybrid
/// (ML-KEM + classical) KEM-DEM. The canonical constant lives here so both
/// the sync service (which must reject hybrid inputs with a clear error) and
/// the async/streaming hybrid paths share it without an import cycle.
const pqForgeHybridKexMetadataKey = 'hybridKex';

/// Metadata key recording a non-default AEAD suite (`chacha20-poly1305`).
/// Absent means AES-256-GCM, so default containers carry no marker. Reserved:
/// the encrypt paths reject caller metadata that already contains it.
const pqForgeAeadSuiteMetadataKey = 'aeadSuite';

/// Metadata key holding the additional-recipient key-wrap entries of a
/// multi-recipient envelope/container (the payload is sealed once; the DEM
/// key is wrapped per extra recipient). Reserved like [pqForgeHybridKexMetadataKey].
const pqForgeRecipientsMetadataKey = 'recipients';

/// Metadata key naming the primary recipient's key id on multi-recipient
/// envelopes, letting a decryptor pick the right unwrap path without trials.
const pqForgeRecipientKeyIdMetadataKey = 'recipientKeyId';

/// Every metadata key pqforge writes itself and therefore refuses from
/// callers, so user metadata can never spoof a container marker.
const pqForgeReservedMetadataKeys = [
  pqForgeHybridKexMetadataKey,
  pqForgeAeadSuiteMetadataKey,
  pqForgeRecipientsMetadataKey,
  pqForgeRecipientKeyIdMetadataKey,
];

/// Throws [PqForgeException] when caller-supplied [metadata] already contains
/// one of the [pqForgeReservedMetadataKeys]. Every encrypt path (sync, async,
/// streaming) runs this before merging its own markers in.
void requireWritableEnvelopeMetadata(Map<String, Object?> metadata) {
  for (final key in pqForgeReservedMetadataKeys) {
    if (metadata.containsKey(key)) {
      throw PqForgeException(
        'metadata already contains "$key"; it is reserved for pqforge '
        'container markers',
      );
    }
  }
}

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

  static PqSignatureAlgorithm? tryById(String id) {
    for (final value in values) {
      if (value.id == id || value.name == id) return value;
    }
    return null;
  }

  static PqSignatureAlgorithm byId(String id) {
    final value = tryById(id);
    if (value == null) {
      throw PqForgeException('Unsupported ML-DSA algorithm: $id');
    }
    return value;
  }
}

/// FIPS 205 SLH-DSA parameter sets composed by pqforge.
///
/// All 12 standardized sets (SHA-2 and SHAKE × 128s/128f/192s/192f/256s/256f).
/// Key generation, custody, and detached `sign`/`verify` are first-class.
/// Envelope headers, streaming signatures, and `hybrid-sign` stay ML-DSA-only:
/// SLH-DSA signatures are 8–50 KiB and the `s` sets are slow by design.
enum PqSlhDsaAlgorithm {
  sha2128s(
    id: 'slh-dsa-sha2-128s',
    name: 'SLH-DSA-SHA2-128s',
    securityCategory: 1,
    publicKeyBytes: 32,
    secretKeyBytes: 64,
    signatureBytes: 7856,
    isFast: false,
  ),
  sha2128f(
    id: 'slh-dsa-sha2-128f',
    name: 'SLH-DSA-SHA2-128f',
    securityCategory: 1,
    publicKeyBytes: 32,
    secretKeyBytes: 64,
    signatureBytes: 17088,
    isFast: true,
  ),
  sha2192s(
    id: 'slh-dsa-sha2-192s',
    name: 'SLH-DSA-SHA2-192s',
    securityCategory: 3,
    publicKeyBytes: 48,
    secretKeyBytes: 96,
    signatureBytes: 16224,
    isFast: false,
  ),
  sha2192f(
    id: 'slh-dsa-sha2-192f',
    name: 'SLH-DSA-SHA2-192f',
    securityCategory: 3,
    publicKeyBytes: 48,
    secretKeyBytes: 96,
    signatureBytes: 35664,
    isFast: true,
  ),
  sha2256s(
    id: 'slh-dsa-sha2-256s',
    name: 'SLH-DSA-SHA2-256s',
    securityCategory: 5,
    publicKeyBytes: 64,
    secretKeyBytes: 128,
    signatureBytes: 29792,
    isFast: false,
  ),
  sha2256f(
    id: 'slh-dsa-sha2-256f',
    name: 'SLH-DSA-SHA2-256f',
    securityCategory: 5,
    publicKeyBytes: 64,
    secretKeyBytes: 128,
    signatureBytes: 49856,
    isFast: true,
  ),
  shake128s(
    id: 'slh-dsa-shake-128s',
    name: 'SLH-DSA-SHAKE-128s',
    securityCategory: 1,
    publicKeyBytes: 32,
    secretKeyBytes: 64,
    signatureBytes: 7856,
    isFast: false,
  ),
  shake128f(
    id: 'slh-dsa-shake-128f',
    name: 'SLH-DSA-SHAKE-128f',
    securityCategory: 1,
    publicKeyBytes: 32,
    secretKeyBytes: 64,
    signatureBytes: 17088,
    isFast: true,
  ),
  shake192s(
    id: 'slh-dsa-shake-192s',
    name: 'SLH-DSA-SHAKE-192s',
    securityCategory: 3,
    publicKeyBytes: 48,
    secretKeyBytes: 96,
    signatureBytes: 16224,
    isFast: false,
  ),
  shake192f(
    id: 'slh-dsa-shake-192f',
    name: 'SLH-DSA-SHAKE-192f',
    securityCategory: 3,
    publicKeyBytes: 48,
    secretKeyBytes: 96,
    signatureBytes: 35664,
    isFast: true,
  ),
  shake256s(
    id: 'slh-dsa-shake-256s',
    name: 'SLH-DSA-SHAKE-256s',
    securityCategory: 5,
    publicKeyBytes: 64,
    secretKeyBytes: 128,
    signatureBytes: 29792,
    isFast: false,
  ),
  shake256f(
    id: 'slh-dsa-shake-256f',
    name: 'SLH-DSA-SHAKE-256f',
    securityCategory: 5,
    publicKeyBytes: 64,
    secretKeyBytes: 128,
    signatureBytes: 49856,
    isFast: true,
  );

  const PqSlhDsaAlgorithm({
    required this.id,
    required this.name,
    required this.securityCategory,
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.signatureBytes,
    required this.isFast,
  });

  final String id;
  final String name;
  final int securityCategory;
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int signatureBytes;

  /// `true` for the `f` (fast) sets; `s` (small signature) sets need an
  /// explicit slow-signing opt-in at the primitive layer.
  final bool isFast;

  /// Filename stem used by `keygen` (`vault.slh-dsa-shake-128f.public.json`).
  String get fileStem => id;

  static const ids = [
    'slh-dsa-sha2-128s',
    'slh-dsa-sha2-128f',
    'slh-dsa-sha2-192s',
    'slh-dsa-sha2-192f',
    'slh-dsa-sha2-256s',
    'slh-dsa-sha2-256f',
    'slh-dsa-shake-128s',
    'slh-dsa-shake-128f',
    'slh-dsa-shake-192s',
    'slh-dsa-shake-192f',
    'slh-dsa-shake-256s',
    'slh-dsa-shake-256f',
  ];

  static PqSlhDsaAlgorithm? tryById(String id) {
    for (final value in values) {
      if (value.id == id || value.name == id) return value;
    }
    return null;
  }

  static PqSlhDsaAlgorithm byId(String id) {
    final value = tryById(id);
    if (value == null) {
      throw PqForgeException('Unsupported SLH-DSA algorithm: $id');
    }
    return value;
  }
}

/// A named composition profile for common post-quantum choices.
class PqForgeProfile {
  const PqForgeProfile({
    required this.name,
    required this.kem,
    required this.signature,
    this.slhDsa = PqSlhDsaAlgorithm.shake128f,
    this.sessionKeyBytes = pqForgeDefaultSessionKeyBytes,
    this.infoPrefix = pqForgeInfoPrefix,
  });

  static const compact = PqForgeProfile(
    name: 'compact',
    kem: PqKemAlgorithm.mlKem512,
    signature: PqSignatureAlgorithm.mlDsa44,
    slhDsa: PqSlhDsaAlgorithm.shake128f,
  );

  static const balanced = PqForgeProfile(
    name: 'balanced',
    kem: PqKemAlgorithm.mlKem768,
    signature: PqSignatureAlgorithm.mlDsa65,
    slhDsa: PqSlhDsaAlgorithm.shake192f,
  );

  static const maximum = PqForgeProfile(
    name: 'maximum',
    kem: PqKemAlgorithm.mlKem1024,
    signature: PqSignatureAlgorithm.mlDsa87,
    slhDsa: PqSlhDsaAlgorithm.shake256f,
  );

  final String name;
  final PqKemAlgorithm kem;
  final PqSignatureAlgorithm signature;

  /// Profile-matched SLH-DSA set used by `keygen` when `--slh-dsa` is omitted.
  /// Compact → SHAKE-128f, balanced → SHAKE-192f, maximum → SHAKE-256f.
  final PqSlhDsaAlgorithm slhDsa;
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

  /// Resolves [name] to a built-in profile, or reconstructs a custom profile
  /// (e.g. a decoupled `--kem`/`--sig` composition) from the algorithms a
  /// serialized envelope carries alongside the name.
  static PqForgeProfile resolve(
    String name,
    PqKemAlgorithm kem,
    PqSignatureAlgorithm? signature,
  ) {
    try {
      return byName(name);
    } on PqForgeException {
      return PqForgeProfile(
        name: name,
        kem: kem,
        signature: signature ?? PqSignatureAlgorithm.mlDsa65,
        slhDsa: switch (kem) {
          PqKemAlgorithm.mlKem512 => PqSlhDsaAlgorithm.shake128f,
          PqKemAlgorithm.mlKem768 => PqSlhDsaAlgorithm.shake192f,
          PqKemAlgorithm.mlKem1024 => PqSlhDsaAlgorithm.shake256f,
        },
      );
    }
  }
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
