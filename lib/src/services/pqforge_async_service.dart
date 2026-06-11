/// Engine-aware and hybrid (ML-KEM + X25519) one-shot envelope encryption.
///
/// Two seams on top of the core [PqForge] facade:
///
/// * [PqForgeAsync] — `encryptAsync`/`decryptAsync`, the engine-pluggable
///   one-shot path. The sync [PqForge.encrypt] is hardwired to the pure-Dart
///   PointyCastle AES-GCM (~1 MiB/s); these run the DEM stage through any
///   [PqForgeAeadEngine] (default: `package:cryptography`, ~10× faster and
///   hardware-backed where available) while producing byte-compatible
///   envelopes — either path decrypts the other's output.
/// * [PqHybridKemDem] — the hybrid KEM-DEM key schedule shared by this
///   one-shot path and the `.pqfs` streaming path: an ephemeral X25519
///   exchange folded into the ML-KEM shared secret with the IETF
///   concatenate-then-KDF combiner, recorded as a self-describing
///   `hybridKex` metadata entry.
///
/// Hybrid envelopes need no format change: the ephemeral public key and
/// classical algorithm feed the KDF (salt and info), so tampering with the
/// marker changes the derived key and fails AEAD authentication even on
/// unsigned envelopes; signed envelopes and streaming headers additionally
/// bind the metadata explicitly.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_fips.dart';
import '../cipher/pq_cipher_suite.dart';
import '../cipher/pq_cryptography_aead_engine.dart';
import '../cipher/pq_pointycastle_aead_engine.dart';
import '../codecs/pq_envelope.dart';
import '../hybrid/pq_classical_hybrid.dart';
import '../hybrid/pq_hybrid_combiner.dart';
import '../primitives/pq_primitives.dart';
import 'pqforge_service.dart';

/// Builds an AEAD engine instance for [provider] — the one mapping shared by
/// the one-shot async path, the streaming cipher, and the CLI.
PqForgeAeadEngine aeadEngineForProvider(
  PqForgeEngineProvider provider, {
  PqForgeCipherSuite cipherSuite = PqForgeCipherSuite.aes256Gcm,
}) => switch (provider) {
  PqForgeEngineProvider.pureDart => PqForgePointyCastleAeadEngine(cipherSuite),
  PqForgeEngineProvider.nativeCryptography => PqForgeCryptographyAeadEngine(
    cipherSuite,
  ),
};

/// The hybrid (classical + post-quantum) KEM-DEM key schedule.
///
/// Pure helpers shared by [PqForgeAsync] and the streaming cipher so both
/// formats derive byte-identical DEM keys from the same inputs.
abstract final class PqHybridKemDem {
  /// Metadata key whose presence marks an envelope/container as hybrid.
  static const metadataKey = pqForgeHybridKexMetadataKey;

  /// True when [metadata] carries the hybrid marker.
  static bool isHybrid(Map<String, Object?> metadata) =>
      metadata.containsKey(metadataKey);

  /// The combiner digest profile paired with [kem] — SHA-512 HKDF for the
  /// NIST level 5 parameter set, SHA-256 otherwise (mirrors the hybrid
  /// key-agreement recipe).
  static PqHybridProfile combinerProfileFor(PqKemAlgorithm kem) =>
      kem == PqKemAlgorithm.mlKem1024
      ? PqHybridProfile.heavy
      : PqHybridProfile.balanced;

  /// Derives the hybrid DEM key: `HKDF(classicalSS ‖ kemSS)` with the KEM
  /// ciphertext and ephemeral public key as salt, domain-separated per
  /// profile, KEM, and classical algorithm.
  ///
  /// Binding [classicalEphemeralPublicKey] into the salt (and [classical]
  /// into the info) makes the metadata marker self-authenticating: any
  /// tamper yields a different key and the AEAD open fails.
  static Uint8List deriveDemKey({
    required PqForgeProfile profile,
    required Uint8List kemSharedSecret,
    required Uint8List kemCiphertext,
    required Uint8List classicalSharedSecret,
    required Uint8List classicalEphemeralPublicKey,
    PqClassicalKeyAgreementAlgorithm classical =
        PqClassicalKeyAgreementAlgorithm.x25519,
  }) {
    return PqForgeCombiner(profile: combinerProfileFor(profile.kem)).combine(
      classicalSharedSecret: classicalSharedSecret,
      postQuantumSharedSecret: kemSharedSecret,
      info: PqBytes.utf8Bytes(
        'pqforge/hybrid-kem-dem/${profile.name}/${profile.kem.id}/'
        '${classical.id}/v1',
      ),
      salt: PqBytes.concat([kemCiphertext, classicalEphemeralPublicKey]),
      length: profile.sessionKeyBytes,
    );
  }

  /// Encryptor side: performs the ephemeral X25519 exchange against
  /// [recipientKexPublicKey], folds it into the ML-KEM secret, and returns
  /// the DEM key plus the `hybridKex` metadata entry the reader needs.
  ///
  /// The classical shared secret is wiped before returning.
  static Future<({Uint8List demKey, Map<String, Object?> metadataEntry})>
  encapsulate({
    required PqForgeProfile profile,
    required Uint8List kemSharedSecret,
    required Uint8List kemCiphertext,
    required Uint8List recipientKexPublicKey,
  }) async {
    final ephemeral = await const PqForgeHybridKeyAgreement()
        .generateClassicalKeyPairBytes();
    final classicalSharedSecret =
        await PqForgeHybridKeyAgreement.x25519SharedSecret(
          secretKey: ephemeral.secretKey,
          remotePublicKey: recipientKexPublicKey,
        );
    try {
      final demKey = deriveDemKey(
        profile: profile,
        kemSharedSecret: kemSharedSecret,
        kemCiphertext: kemCiphertext,
        classicalSharedSecret: classicalSharedSecret,
        classicalEphemeralPublicKey: ephemeral.publicKey,
      );
      return (
        demKey: demKey,
        metadataEntry: <String, Object?>{
          metadataKey: <String, Object?>{
            'algorithm': PqClassicalKeyAgreementAlgorithm.x25519.id,
            'ephemeralPublicKey': base64Encode(ephemeral.publicKey),
          },
        },
      );
    } finally {
      PqForgeCombiner.wipe(classicalSharedSecret);
      PqForgeCombiner.wipe(ephemeral.secretKey);
    }
  }

  /// Decryptor side: recomputes the hybrid DEM key from the `hybridKex`
  /// [metadata] marker and the recipient's X25519 [recipientKexSecretKey].
  ///
  /// Throws [PqForgeException] when the marker is malformed or names an
  /// unsupported classical algorithm.
  static Future<Uint8List> demKeyForOpen({
    required PqForgeProfile profile,
    required Uint8List kemSharedSecret,
    required Uint8List kemCiphertext,
    required Map<String, Object?> metadata,
    required Uint8List recipientKexSecretKey,
  }) async {
    final marker = parseMetadata(metadata);
    if (marker == null) {
      throw const PqForgeException(
        'Envelope metadata carries no hybridKex marker',
      );
    }
    final classicalSharedSecret =
        await PqForgeHybridKeyAgreement.x25519SharedSecret(
          secretKey: recipientKexSecretKey,
          remotePublicKey: marker.ephemeralPublicKey,
        );
    try {
      return deriveDemKey(
        profile: profile,
        kemSharedSecret: kemSharedSecret,
        kemCiphertext: kemCiphertext,
        classicalSharedSecret: classicalSharedSecret,
        classicalEphemeralPublicKey: marker.ephemeralPublicKey,
        classical: marker.algorithm,
      );
    } finally {
      PqForgeCombiner.wipe(classicalSharedSecret);
    }
  }

  /// Parses the `hybridKex` marker out of [metadata], or returns null for a
  /// pure post-quantum envelope.
  static ({
    PqClassicalKeyAgreementAlgorithm algorithm,
    Uint8List ephemeralPublicKey,
  })?
  parseMetadata(Map<String, Object?> metadata) {
    final raw = metadata[metadataKey];
    if (raw == null) return null;
    if (raw is! Map) {
      throw const PqForgeException('Malformed hybridKex metadata entry');
    }
    final algorithmId = raw['algorithm'];
    final encodedKey = raw['ephemeralPublicKey'];
    if (algorithmId is! String || encodedKey is! String) {
      throw const PqForgeException('Malformed hybridKex metadata entry');
    }
    final algorithm = PqClassicalKeyAgreementAlgorithm.byId(algorithmId);
    final Uint8List ephemeralPublicKey;
    try {
      ephemeralPublicKey = base64Decode(encodedKey);
    } on FormatException {
      throw const PqForgeException('Malformed hybridKex ephemeral public key');
    }
    requireLength(
      'ephemeralPublicKey',
      ephemeralPublicKey,
      algorithm.publicKeyBytes,
    );
    return (algorithm: algorithm, ephemeralPublicKey: ephemeralPublicKey);
  }
}

/// Engine-pluggable (and optionally hybrid) one-shot envelope encryption.
extension PqForgeAsync on PqForge {
  /// Encrypts [plaintext] into a one-shot envelope, running the DEM stage on
  /// [engine] (default: the `package:cryptography` AES-256-GCM backend).
  ///
  /// When [recipientKexPublicKey] (a raw 32-byte X25519 public key) is
  /// supplied the envelope is **hybrid**: the DEM key combines the ML-KEM
  /// shared secret with an ephemeral X25519 exchange, so confidentiality
  /// holds as long as *either* assumption stands. Output is byte-compatible
  /// with [PqForge.encrypt] for the non-hybrid case — either engine's output
  /// opens under the other.
  Future<PqEnvelope> encryptAsync(
    Uint8List recipientPublicKey,
    Uint8List plaintext, {
    Uint8List? recipientKexPublicKey,
    PqForgeAeadEngine? engine,
    PqForgeProfile? profile,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
  }) async {
    final selected = profile ?? this.profile;
    final aead = engine ?? _defaultEngine();
    PqFipsMode.requireApprovedSuite(aead.cipherSuite);
    if (PqHybridKemDem.isHybrid(metadata)) {
      throw const PqForgeException(
        'metadata already contains a hybridKex entry; it is reserved for the '
        'hybrid KEM-DEM marker',
      );
    }

    final encapsulated = PqKemPrimitives.encapsulate(
      selected.kem,
      recipientPublicKey,
    );
    final Uint8List demKey;
    var effectiveMetadata = metadata;
    if (recipientKexPublicKey == null) {
      demKey = PqForge.deriveDemKey(
        selected,
        encapsulated.sharedSecret,
        encapsulated.ciphertext,
      );
    } else {
      final hybrid = await PqHybridKemDem.encapsulate(
        profile: selected,
        kemSharedSecret: encapsulated.sharedSecret,
        kemCiphertext: encapsulated.ciphertext,
        recipientKexPublicKey: recipientKexPublicKey,
      );
      demKey = hybrid.demKey;
      effectiveMetadata = {...metadata, ...hybrid.metadataEntry};
    }

    final nonce = PqBytes.randomBytes(pqForgeDefaultAeadNonceBytes);
    final payload = await aead.seal(
      key: demKey,
      nonce: nonce,
      plaintext: plaintext,
      aad: aad ?? encapsulated.ciphertext,
    );
    return assembleSealedEnvelope(
      profile: selected,
      kemCiphertext: encapsulated.ciphertext,
      nonce: nonce,
      payload: payload,
      aad: aad,
      metadata: effectiveMetadata,
      signerSecretKey: signerSecretKey,
      signatureAlgorithm: signatureAlgorithm,
      signerKeyId: signerKeyId,
    );
  }

  /// Decrypts a one-shot [envelope] on [engine], auto-detecting hybrid
  /// envelopes from their `hybridKex` metadata marker.
  ///
  /// Hybrid envelopes require [recipientKexSecretKey] (the raw 32-byte X25519
  /// secret matching the public key the sender encrypted to); a missing key
  /// fails with a descriptive [PqForgeException] before any AEAD work. A
  /// supplied kex key is ignored for non-hybrid envelopes.
  Future<Uint8List> decryptAsync(
    Uint8List recipientSecretKey,
    PqEnvelope envelope, {
    Uint8List? recipientKexSecretKey,
    PqForgeAeadEngine? engine,
    Uint8List? aad,
    Uint8List? signerPublicKey,
  }) async {
    final aead = engine ?? _defaultEngine();
    PqFipsMode.requireApprovedSuite(aead.cipherSuite);
    verifyEnvelopeForOpen(envelope, aad: aad, signerPublicKey: signerPublicKey);

    final sharedSecret = PqKemPrimitives.decapsulate(
      envelope.kemAlgorithm,
      recipientSecretKey,
      envelope.kemCiphertext,
    );
    final Uint8List demKey;
    if (PqHybridKemDem.isHybrid(envelope.metadata)) {
      if (recipientKexSecretKey == null) {
        throw const PqForgeException(
          'This envelope uses hybrid ML-KEM + X25519 encryption; the '
          'recipient X25519 secret key is required to decrypt it',
        );
      }
      demKey = await PqHybridKemDem.demKeyForOpen(
        profile: envelope.profile,
        kemSharedSecret: sharedSecret,
        kemCiphertext: envelope.kemCiphertext,
        metadata: envelope.metadata,
        recipientKexSecretKey: recipientKexSecretKey,
      );
    } else {
      demKey = PqForge.deriveDemKey(
        envelope.profile,
        sharedSecret,
        envelope.kemCiphertext,
      );
    }
    return aead.open(
      key: demKey,
      nonce: envelope.nonce,
      cipherTextWithTag: envelope.payload,
      aad: aad ?? envelope.kemCiphertext,
    );
  }
}

PqForgeAeadEngine _defaultEngine() =>
    PqForgeCryptographyAeadEngine(PqForgeCipherSuite.aes256Gcm);
