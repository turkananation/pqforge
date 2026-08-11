import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

class PqForgeHybridSigner {
  const PqForgeHybridSigner({
    this.profile = PqForgeProfile.balanced,
    this.classicalAlgorithm = PqClassicalSignatureAlgorithm.ed25519,
  });

  final PqForgeProfile profile;
  final PqClassicalSignatureAlgorithm classicalAlgorithm;

  /// Generates a classical key pair for [classicalAlgorithm].
  ///
  /// [seed] (a 32-byte seed) is supported only for Ed25519; ECDSA-P256 keys are
  /// always randomly generated and reject a supplied seed.
  Future<PqClassicalSignatureKeyPair> generateClassicalKeyPair({
    Uint8List? seed,
  }) async {
    switch (classicalAlgorithm) {
      case PqClassicalSignatureAlgorithm.ed25519:
        final pair = await PqClassical.provider.ed25519GenerateKeyPair(
          seed: seed,
        );
        return PqClassicalSignatureKeyPair(
          algorithm: PqClassicalSignatureAlgorithm.ed25519,
          publicKey: pair.publicKey,
          secretKey: pair.secretKey,
        );
      case PqClassicalSignatureAlgorithm.ecdsaP256:
        if (seed != null) {
          throw const PqForgeException(
            'Seeded key generation is not supported for ECDSA-P256',
          );
        }
        final pair = await PqClassical.provider.ecdsaP256GenerateKeyPair();
        return PqClassicalSignatureKeyPair(
          algorithm: PqClassicalSignatureAlgorithm.ecdsaP256,
          publicKey: pair.publicKey,
          secretKey: pair.secretKey,
        );
    }
  }

  /// Reconstructs a usable [PqClassicalSignatureKeyPair] from a stored 32-byte
  /// [secretKey] for [classicalAlgorithm], deriving the public key when it is
  /// not supplied.
  ///
  /// This lets callers (such as the CLI) persist only the secret key and still
  /// sign later: for Ed25519 the public key is recovered from the seed, and for
  /// ECDSA-P256 it is recomputed as `d · G` by the classical provider.
  /// A supplied [publicKey] is used as-is (and length-checked by the key-pair
  /// constructor) without re-derivation.
  Future<PqClassicalSignatureKeyPair> classicalKeyPairFromSecret(
    Uint8List secretKey, {
    Uint8List? publicKey,
  }) async {
    switch (classicalAlgorithm) {
      case PqClassicalSignatureAlgorithm.ed25519:
        final derived =
            publicKey ??
            await PqClassical.provider.ed25519PublicKeyFromSeed(secretKey);
        return PqClassicalSignatureKeyPair(
          algorithm: PqClassicalSignatureAlgorithm.ed25519,
          publicKey: derived,
          secretKey: secretKey,
        );
      case PqClassicalSignatureAlgorithm.ecdsaP256:
        final derived =
            publicKey ??
            await PqClassical.provider.ecdsaP256PublicKeyFromPrivate(secretKey);
        return PqClassicalSignatureKeyPair(
          algorithm: PqClassicalSignatureAlgorithm.ecdsaP256,
          publicKey: derived,
          secretKey: secretKey,
        );
    }
  }

  /// Signs [message] with ML-DSA and the classical algorithm, binding [context].
  Future<PqHybridSignature> sign({
    required Uint8List pqcSecretKey,
    required PqClassicalSignatureKeyPair classicalKeyPair,
    required Uint8List message,
    Uint8List? context,
    PqSignatureAlgorithm? pqcAlgorithm,
    PqDualSignaturePolicy policy = PqDualSignaturePolicy.requireBoth,
  }) async {
    if (classicalKeyPair.algorithm != classicalAlgorithm) {
      throw PqForgeException(
        'Classical key pair algorithm ${classicalKeyPair.algorithm.id} does '
        'not match signer algorithm ${classicalAlgorithm.id}',
      );
    }
    final selectedPqc = pqcAlgorithm ?? profile.signature;
    final boundMessage = _hybridSignatureMessage(message, context);
    final classicalSignature = await _signClassical(
      classicalKeyPair,
      boundMessage,
    );
    final dual = PqForge(profile: profile).dualSign(
      secretKey: pqcSecretKey,
      message: boundMessage,
      classicalSignature: classicalSignature,
      algorithm: selectedPqc,
      policy: policy,
    );
    return PqHybridSignature(
      pqcSignature: dual.pqcSignature,
      classicalSignature: dual.classicalSignature,
      pqcAlgorithm: selectedPqc,
      classicalAlgorithm: classicalAlgorithm,
      policy: policy,
    );
  }

  /// Verifies a [signature] over [message] under both public keys.
  ///
  /// [classicalPublicKey] is the raw classical public key (Ed25519: 32 bytes;
  /// ECDSA-P256: the 65-byte uncompressed SEC1 point).
  Future<bool> verify({
    required Uint8List pqcPublicKey,
    required Uint8List classicalPublicKey,
    required Uint8List message,
    required PqHybridSignature signature,
    Uint8List? context,
  }) async {
    if (signature.classicalAlgorithm != classicalAlgorithm) return false;
    final boundMessage = _hybridSignatureMessage(message, context);
    final pqcValid = PqForge(profile: profile).verify(
      pqcPublicKey,
      boundMessage,
      signature.pqcSignature,
      algorithm: signature.pqcAlgorithm,
      context: PqBytes.utf8Bytes('pqforge/dual-signature/v1'),
    );
    final classicalValid = await _verifyClassical(
      classicalAlgorithm,
      classicalPublicKey,
      boundMessage,
      signature.classicalSignature,
    );
    return signature.dualSignature.combine(pqcValid, classicalValid);
  }

  static Future<Uint8List> _signClassical(
    PqClassicalSignatureKeyPair keyPair,
    Uint8List boundMessage,
  ) {
    switch (keyPair.algorithm) {
      case PqClassicalSignatureAlgorithm.ed25519:
        return PqClassical.provider.ed25519Sign(
          secretKey: keyPair.secretKey,
          publicKey: keyPair.publicKey,
          message: boundMessage,
        );
      case PqClassicalSignatureAlgorithm.ecdsaP256:
        return PqClassical.provider.ecdsaP256Sign(
          secretKey: keyPair.secretKey,
          message: boundMessage,
        );
    }
  }

  static Future<bool> _verifyClassical(
    PqClassicalSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List boundMessage,
    Uint8List signatureBytes,
  ) {
    switch (algorithm) {
      case PqClassicalSignatureAlgorithm.ed25519:
        return PqClassical.provider.ed25519Verify(
          publicKey: publicKey,
          message: boundMessage,
          signature: signatureBytes,
        );
      case PqClassicalSignatureAlgorithm.ecdsaP256:
        return PqClassical.provider.ecdsaP256Verify(
          publicKey: publicKey,
          message: boundMessage,
          signature: signatureBytes,
        );
    }
  }
}

Uint8List _hybridSignatureMessage(Uint8List message, Uint8List? context) {
  return PqBytes.lengthPrefixed([
    PqBytes.utf8Bytes('pqforge/built-in-hybrid-signature/v1'),
    context ?? Uint8List(0),
    message,
  ]);
}
