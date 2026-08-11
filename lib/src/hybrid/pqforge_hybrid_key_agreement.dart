import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pqforge/pqforge.dart';

class PqForgeHybridKeyAgreement {
  const PqForgeHybridKeyAgreement({
    this.profile = PqForgeProfile.balanced,
    this.classicalAlgorithm = PqClassicalKeyAgreementAlgorithm.x25519,
  });

  final PqForgeProfile profile;
  final PqClassicalKeyAgreementAlgorithm classicalAlgorithm;

  /// Generates a long-term X25519 key-agreement key pair.
  ///
  /// The raw keygen delegates to [PqClassical.provider] (native-accelerated when
  /// a backend is registered; byte-identical on the default provider), and the
  /// result is wrapped as a `package:cryptography` [crypto.SimpleKeyPair] for the
  /// [accept] API.
  Future<crypto.SimpleKeyPair> generateClassicalKeyPair({
    Uint8List? seed,
  }) async {
    final pair = await PqClassical.provider.x25519GenerateKeyPair(seed: seed);
    return crypto.SimpleKeyPairData(
      pair.secretKey,
      publicKey: crypto.SimplePublicKey(
        pair.publicKey,
        type: crypto.KeyPairType.x25519,
      ),
      type: crypto.KeyPairType.x25519,
    );
  }

  /// Generates an X25519 key-agreement key pair as raw 32-byte arrays.
  ///
  /// A byte-oriented companion to [generateClassicalKeyPair] for callers that
  /// persist keys as bytes (such as the CLI) rather than holding a live
  /// `package:cryptography` `SimpleKeyPair`.
  Future<({Uint8List publicKey, Uint8List secretKey})>
  generateClassicalKeyPairBytes({Uint8List? seed}) =>
      PqClassical.provider.x25519GenerateKeyPair(seed: seed);

  /// X25519 ECDH between a raw 32-byte [secretKey] (ours) and a raw 32-byte
  /// [remotePublicKey] (theirs), returning the 32-byte shared secret.
  ///
  /// The byte-oriented companion to [initiate]/[accept] for callers that
  /// persist keys as raw bytes (the CLI, the hybrid KEM-DEM file paths). The
  /// caller owns the returned buffer and should wipe it once consumed.
  static Future<Uint8List> x25519SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) {
    requireLength('secretKey', secretKey, 32);
    requireLength('remotePublicKey', remotePublicKey, 32);
    return PqClassical.provider.x25519SharedSecret(
      secretKey: secretKey,
      remotePublicKey: remotePublicKey,
    );
  }

  Future<PqHybridKeyAgreementResult> initiate({
    required crypto.SimplePublicKey serverClassicalPublicKey,
    required Uint8List serverKemPublicKey,
    required Uint8List deploymentSalt,
    Uint8List? transcriptContext,
    Uint8List? roleContext,
  }) async {
    _requireX25519PublicKey(serverClassicalPublicKey);
    requireLength(
      'serverKemPublicKey',
      serverKemPublicKey,
      profile.kem.publicKeyBytes,
    );
    // Route the ephemeral X25519 keygen and ECDH through the classical seam so a
    // registered native provider accelerates the full handshake (the default
    // provider is byte-identical). The seam hands back raw bytes, so the
    // ephemeral secret is wiped in the `finally` below.
    final clientKeyPair = await PqClassical.provider.x25519GenerateKeyPair();
    Uint8List? classicalSharedSecret;
    Uint8List? latticeSharedSecret;
    try {
      classicalSharedSecret = await PqClassical.provider.x25519SharedSecret(
        secretKey: clientKeyPair.secretKey,
        remotePublicKey: Uint8List.fromList(serverClassicalPublicKey.bytes),
      );
      final kem = PqKemPrimitives.encapsulate(profile.kem, serverKemPublicKey);
      latticeSharedSecret = PqBytes.copy(kem.sharedSecret);
      final request = PqHybridKeyAgreementRequest(
        profile: profile,
        classicalAlgorithm: classicalAlgorithm,
        serverClassicalPublicKey: Uint8List.fromList(
          serverClassicalPublicKey.bytes,
        ),
        serverKemPublicKey: serverKemPublicKey,
        clientClassicalPublicKey: Uint8List.fromList(clientKeyPair.publicKey),
        kemCiphertext: kem.ciphertext,
        transcriptContext: transcriptContext,
      );
      final transcriptHash = request.computeTranscriptHash();
      return PqHybridKeyAgreementResult(
        request: PqHybridKeyAgreementRequest(
          profile: profile,
          classicalAlgorithm: classicalAlgorithm,
          serverClassicalPublicKey: request.serverClassicalPublicKey,
          serverKemPublicKey: request.serverKemPublicKey,
          clientClassicalPublicKey: request.clientClassicalPublicKey,
          kemCiphertext: request.kemCiphertext,
          transcriptContext: request.transcriptContext,
          transcriptHash: transcriptHash,
        ),
        sessionKey: _deriveSessionKey(
          profile: profile,
          classicalSharedSecret: classicalSharedSecret,
          latticeSharedSecret: latticeSharedSecret,
          deploymentSalt: deploymentSalt,
          transcriptHash: transcriptHash,
          roleContext: roleContext,
        ),
      );
    } finally {
      PqForgeCombiner.wipe(clientKeyPair.secretKey);
      if (classicalSharedSecret != null) {
        PqForgeCombiner.wipe(classicalSharedSecret);
      }
      if (latticeSharedSecret != null) {
        PqForgeCombiner.wipe(latticeSharedSecret);
      }
    }
  }

  Future<Uint8List> accept({
    required crypto.SimpleKeyPair serverClassicalKeyPair,
    required Uint8List serverKemSecretKey,
    required PqHybridKeyAgreementRequest request,
    required Uint8List deploymentSalt,
    Uint8List? roleContext,
  }) async {
    if (request.classicalAlgorithm != classicalAlgorithm) {
      throw const PqForgeException(
        'Hybrid request classical algorithm mismatch',
      );
    }
    if (request.profile.kem != profile.kem ||
        request.profile.signature != profile.signature) {
      throw const PqForgeException('Hybrid request profile mismatch');
    }
    final serverPublicKey = await serverClassicalKeyPair.extractPublicKey();
    if (!PqBytes.constantTimeEquals(
      Uint8List.fromList(serverPublicKey.bytes),
      request.serverClassicalPublicKey,
    )) {
      throw const PqForgeException('Hybrid request server X25519 key mismatch');
    }
    final transcriptHash = request.requireTranscriptHash();
    Uint8List? classicalSharedSecret;
    Uint8List? latticeSharedSecret;
    try {
      // ECDH via the classical seam (native-accelerated when a provider is
      // registered). Extract the server's raw scalar for the seam and wipe it
      // the moment the shared secret is derived.
      final serverSecretKey = Uint8List.fromList(
        await serverClassicalKeyPair.extractPrivateKeyBytes(),
      );
      try {
        classicalSharedSecret = await PqClassical.provider.x25519SharedSecret(
          secretKey: serverSecretKey,
          remotePublicKey: request.clientClassicalPublicKey,
        );
      } finally {
        PqForgeCombiner.wipe(serverSecretKey);
      }
      latticeSharedSecret = PqKemPrimitives.decapsulate(
        profile.kem,
        serverKemSecretKey,
        request.kemCiphertext,
      );
      return _deriveSessionKey(
        profile: profile,
        classicalSharedSecret: classicalSharedSecret,
        latticeSharedSecret: latticeSharedSecret,
        deploymentSalt: deploymentSalt,
        transcriptHash: transcriptHash,
        roleContext: roleContext,
      );
    } finally {
      if (classicalSharedSecret != null) {
        PqForgeCombiner.wipe(classicalSharedSecret);
      }
      if (latticeSharedSecret != null) {
        PqForgeCombiner.wipe(latticeSharedSecret);
      }
    }
  }
}

Uint8List _deriveSessionKey({
  required PqForgeProfile profile,
  required Uint8List classicalSharedSecret,
  required Uint8List latticeSharedSecret,
  required Uint8List deploymentSalt,
  required Uint8List transcriptHash,
  Uint8List? roleContext,
}) {
  requireLength('classicalSharedSecret', classicalSharedSecret, 32);
  requireLength('latticeSharedSecret', latticeSharedSecret, 32);
  requireLength(
    'deploymentSalt',
    deploymentSalt,
    pqForgeDefaultDeploymentSaltBytes,
  );
  requireLength('transcriptHash', transcriptHash, 32);
  return PqForgeCombiner(profile: _combinerProfile(profile)).combine(
    classicalSharedSecret: classicalSharedSecret,
    postQuantumSharedSecret: latticeSharedSecret,
    info: PqBytes.concat([
      PqBytes.utf8Bytes(profile.infoPrefix),
      PqBytes.utf8Bytes('/hybrid-key-agreement/v1'),
      ?roleContext,
    ]),
    salt: PqBytes.concat([deploymentSalt, transcriptHash]),
    length: profile.sessionKeyBytes,
  );
}

PqHybridProfile _combinerProfile(PqForgeProfile profile) {
  return profile.kem == PqKemAlgorithm.mlKem1024
      ? PqHybridProfile.heavy
      : PqHybridProfile.balanced;
}

void _requireX25519PublicKey(crypto.SimplePublicKey publicKey) {
  if (publicKey.type != crypto.KeyPairType.x25519 ||
      publicKey.bytes.length != 32) {
    throw const PqForgeException('Expected a 32-byte X25519 public key');
  }
}
