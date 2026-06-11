/// Batteries-included classical + post-quantum hybrid helpers.
///
/// Provides X25519 + ML-KEM key agreement (via `package:cryptography`) and
/// hybrid signatures pairing ML-DSA with a classical signature — Ed25519
/// (`package:cryptography`) or ECDSA over NIST P-256 ([PqEcdsaP256], pure-Dart
/// PointyCastle). Surfaced through the single `package:pqforge/pqforge.dart`
/// entrypoint.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;

import '../algorithms/pq_algorithms.dart';
import '../primitives/pq_primitives.dart';
import '../recipes/pq_recipes.dart';
import '../services/pqforge_service.dart';
import 'pq_ecdsa_p256.dart';
import 'pq_hybrid_combiner.dart';

enum PqClassicalKeyAgreementAlgorithm {
  x25519(id: 'x25519', publicKeyBytes: 32, sharedSecretBytes: 32);

  const PqClassicalKeyAgreementAlgorithm({
    required this.id,
    required this.publicKeyBytes,
    required this.sharedSecretBytes,
  });

  final String id;
  final int publicKeyBytes;
  final int sharedSecretBytes;

  static PqClassicalKeyAgreementAlgorithm byId(String id) {
    for (final value in values) {
      if (value.id == id) return value;
    }
    throw PqForgeException('Unsupported classical KEX algorithm: $id');
  }
}

enum PqClassicalSignatureAlgorithm {
  ed25519(
    id: 'ed25519',
    publicKeyBytes: 32,
    secretKeyBytes: 32,
    signatureBytes: 64,
  ),
  ecdsaP256(
    id: 'ecdsa-p256',
    publicKeyBytes: 65,
    secretKeyBytes: 32,
    signatureBytes: 64,
  );

  const PqClassicalSignatureAlgorithm({
    required this.id,
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.signatureBytes,
  });

  final String id;

  /// Public-key length in bytes (Ed25519: 32; ECDSA-P256 uncompressed: 65).
  final int publicKeyBytes;

  /// Secret-key length in bytes (the 32-byte Ed25519 seed / EC scalar).
  final int secretKeyBytes;

  /// Signature length in bytes (Ed25519: 64; ECDSA-P256 raw `r||s`: 64).
  final int signatureBytes;

  static PqClassicalSignatureAlgorithm byId(String id) {
    for (final value in values) {
      if (value.id == id) return value;
    }
    throw PqForgeException('Unsupported classical signature algorithm: $id');
  }
}

/// A classical signature key pair as raw bytes, so both backends — Ed25519 via
/// `package:cryptography` and ECDSA-P256 via [PqEcdsaP256] — share one type.
class PqClassicalSignatureKeyPair {
  PqClassicalSignatureKeyPair({
    required this.algorithm,
    required Uint8List publicKey,
    required Uint8List secretKey,
  }) : publicKey = PqBytes.copy(publicKey),
       secretKey = PqBytes.copy(secretKey) {
    requireLength('publicKey', this.publicKey, algorithm.publicKeyBytes);
    requireLength('secretKey', this.secretKey, algorithm.secretKeyBytes);
  }

  final PqClassicalSignatureAlgorithm algorithm;
  final Uint8List publicKey;
  final Uint8List secretKey;
}

class PqHybridKeyAgreementRequest {
  PqHybridKeyAgreementRequest({
    required this.profile,
    this.classicalAlgorithm = PqClassicalKeyAgreementAlgorithm.x25519,
    required Uint8List serverClassicalPublicKey,
    required Uint8List serverKemPublicKey,
    required Uint8List clientClassicalPublicKey,
    required Uint8List kemCiphertext,
    Uint8List? transcriptContext,
    Uint8List? transcriptHash,
  }) : serverClassicalPublicKey = PqBytes.copy(serverClassicalPublicKey),
       serverKemPublicKey = PqBytes.copy(serverKemPublicKey),
       clientClassicalPublicKey = PqBytes.copy(clientClassicalPublicKey),
       kemCiphertext = PqBytes.copy(kemCiphertext),
       transcriptContext = transcriptContext == null
           ? Uint8List(0)
           : PqBytes.copy(transcriptContext),
       transcriptHash = transcriptHash == null
           ? null
           : PqBytes.copy(transcriptHash) {
    requireLength(
      'serverClassicalPublicKey',
      this.serverClassicalPublicKey,
      classicalAlgorithm.publicKeyBytes,
    );
    requireLength(
      'clientClassicalPublicKey',
      this.clientClassicalPublicKey,
      classicalAlgorithm.publicKeyBytes,
    );
    requireLength(
      'serverKemPublicKey',
      this.serverKemPublicKey,
      profile.kem.publicKeyBytes,
    );
    requireLength(
      'kemCiphertext',
      this.kemCiphertext,
      profile.kem.ciphertextBytes,
    );
    if (this.transcriptHash != null) {
      requireLength('transcriptHash', this.transcriptHash!, 32);
    }
  }

  final PqForgeProfile profile;
  final PqClassicalKeyAgreementAlgorithm classicalAlgorithm;
  final Uint8List serverClassicalPublicKey;
  final Uint8List serverKemPublicKey;
  final Uint8List clientClassicalPublicKey;
  final Uint8List kemCiphertext;
  final Uint8List transcriptContext;
  final Uint8List? transcriptHash;

  Uint8List transcript() => PqBytes.lengthPrefixed([
    PqBytes.utf8Bytes('pqforge/hybrid-key-agreement/v1'),
    PqBytes.utf8Bytes(profile.name),
    PqBytes.utf8Bytes(profile.kem.id),
    PqBytes.utf8Bytes(classicalAlgorithm.id),
    serverClassicalPublicKey,
    serverKemPublicKey,
    clientClassicalPublicKey,
    kemCiphertext,
    transcriptContext,
  ]);

  Uint8List computeTranscriptHash() => PqBytes.sha256(transcript());

  Uint8List requireTranscriptHash() {
    final supplied = transcriptHash;
    final actual = computeTranscriptHash();
    if (supplied != null && !PqBytes.constantTimeEquals(supplied, actual)) {
      throw const PqForgeException('Hybrid transcript hash mismatch');
    }
    return actual;
  }

  Map<String, Object?> toJson() => {
    'version': 1,
    'profile': profile.name,
    'kemAlgorithm': profile.kem.id,
    'signatureAlgorithm': profile.signature.id,
    'classicalAlgorithm': classicalAlgorithm.id,
    'serverClassicalPublicKey': base64Encode(serverClassicalPublicKey),
    'serverKemPublicKey': base64Encode(serverKemPublicKey),
    'clientClassicalPublicKey': base64Encode(clientClassicalPublicKey),
    'kemCiphertext': base64Encode(kemCiphertext),
    'transcriptContext': base64Encode(transcriptContext),
    'transcriptHash': base64Encode(transcriptHash ?? computeTranscriptHash()),
  };

  static PqHybridKeyAgreementRequest fromJson(Map<String, Object?> json) {
    final version = json['version'] as int? ?? 1;
    if (version != 1) {
      throw PqForgeException('Unsupported hybrid request version: $version');
    }
    final kem = PqKemAlgorithm.byId(json['kemAlgorithm'] as String);
    final signature = PqSignatureAlgorithm.byId(
      json['signatureAlgorithm'] as String,
    );
    return PqHybridKeyAgreementRequest(
      profile: PqForgeProfile(
        name: json['profile'] as String,
        kem: kem,
        signature: signature,
      ),
      classicalAlgorithm: PqClassicalKeyAgreementAlgorithm.byId(
        json['classicalAlgorithm'] as String,
      ),
      serverClassicalPublicKey: base64Decode(
        json['serverClassicalPublicKey'] as String,
      ),
      serverKemPublicKey: base64Decode(json['serverKemPublicKey'] as String),
      clientClassicalPublicKey: base64Decode(
        json['clientClassicalPublicKey'] as String,
      ),
      kemCiphertext: base64Decode(json['kemCiphertext'] as String),
      transcriptContext: base64Decode(
        json['transcriptContext'] as String? ?? '',
      ),
      transcriptHash: base64Decode(json['transcriptHash'] as String),
    );
  }
}

class PqHybridKeyAgreementResult {
  PqHybridKeyAgreementResult({
    required this.request,
    required Uint8List sessionKey,
  }) : sessionKey = PqBytes.copy(sessionKey);

  final PqHybridKeyAgreementRequest request;
  final Uint8List sessionKey;
}

class PqForgeHybridKeyAgreement {
  const PqForgeHybridKeyAgreement({
    this.profile = PqForgeProfile.balanced,
    this.classicalAlgorithm = PqClassicalKeyAgreementAlgorithm.x25519,
  });

  final PqForgeProfile profile;
  final PqClassicalKeyAgreementAlgorithm classicalAlgorithm;

  Future<crypto.SimpleKeyPair> generateClassicalKeyPair({Uint8List? seed}) {
    return seed == null
        ? crypto.X25519().newKeyPair()
        : crypto.X25519().newKeyPairFromSeed(seed);
  }

  /// Generates an X25519 key-agreement key pair as raw 32-byte arrays.
  ///
  /// A byte-oriented companion to [generateClassicalKeyPair] for callers that
  /// persist keys as bytes (such as the CLI) rather than holding a live
  /// `package:cryptography` `SimpleKeyPair`.
  Future<({Uint8List publicKey, Uint8List secretKey})>
  generateClassicalKeyPairBytes({Uint8List? seed}) async {
    final keyPair = await generateClassicalKeyPair(seed: seed);
    try {
      final publicKey = await keyPair.extractPublicKey();
      return (
        publicKey: Uint8List.fromList(publicKey.bytes),
        secretKey: Uint8List.fromList(await keyPair.extractPrivateKeyBytes()),
      );
    } finally {
      keyPair.destroy();
    }
  }

  /// X25519 ECDH between a raw 32-byte [secretKey] (ours) and a raw 32-byte
  /// [remotePublicKey] (theirs), returning the 32-byte shared secret.
  ///
  /// The byte-oriented companion to [initiate]/[accept] for callers that
  /// persist keys as raw bytes (the CLI, the hybrid KEM-DEM file paths). The
  /// caller owns the returned buffer and should wipe it once consumed.
  static Future<Uint8List> x25519SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) async {
    requireLength('secretKey', secretKey, 32);
    requireLength('remotePublicKey', remotePublicKey, 32);
    final x25519 = crypto.X25519();
    // An X25519 secret key IS its seed, so the full key pair (and the public
    // key package:cryptography insists on) is reconstructible from it.
    final keyPair = await x25519.newKeyPairFromSeed(secretKey);
    try {
      final shared = await x25519.sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: crypto.SimplePublicKey(
          remotePublicKey,
          type: crypto.KeyPairType.x25519,
        ),
      );
      return Uint8List.fromList(await shared.extractBytes());
    } finally {
      keyPair.destroy();
    }
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
    final x25519 = crypto.X25519();
    final clientKeyPair = await x25519.newKeyPair();
    Uint8List? classicalSharedSecret;
    Uint8List? latticeSharedSecret;
    try {
      final clientPublicKey = await clientKeyPair.extractPublicKey();
      final sharedSecret = await x25519.sharedSecretKey(
        keyPair: clientKeyPair,
        remotePublicKey: serverClassicalPublicKey,
      );
      classicalSharedSecret = Uint8List.fromList(
        await sharedSecret.extractBytes(),
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
        clientClassicalPublicKey: Uint8List.fromList(clientPublicKey.bytes),
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
      clientKeyPair.destroy();
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
      final sharedSecret = await crypto.X25519().sharedSecretKey(
        keyPair: serverClassicalKeyPair,
        remotePublicKey: crypto.SimplePublicKey(
          request.clientClassicalPublicKey,
          type: crypto.KeyPairType.x25519,
        ),
      );
      classicalSharedSecret = Uint8List.fromList(
        await sharedSecret.extractBytes(),
      );
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

class PqHybridSignature {
  PqHybridSignature({
    required Uint8List pqcSignature,
    required Uint8List classicalSignature,
    required this.pqcAlgorithm,
    required this.classicalAlgorithm,
    this.policy = PqDualSignaturePolicy.requireBoth,
  }) : pqcSignature = PqBytes.copy(pqcSignature),
       classicalSignature = PqBytes.copy(classicalSignature) {
    requireLength(
      'pqcSignature',
      this.pqcSignature,
      pqcAlgorithm.signatureBytes,
    );
    requireLength(
      'classicalSignature',
      this.classicalSignature,
      classicalAlgorithm.signatureBytes,
    );
  }

  final Uint8List pqcSignature;
  final Uint8List classicalSignature;
  final PqSignatureAlgorithm pqcAlgorithm;
  final PqClassicalSignatureAlgorithm classicalAlgorithm;
  final PqDualSignaturePolicy policy;

  PqDualSignature get dualSignature => PqDualSignature(
    pqcSignature: pqcSignature,
    classicalSignature: classicalSignature,
    policy: policy,
  );

  Map<String, Object?> toJson() => {
    'version': 1,
    'pqcAlgorithm': pqcAlgorithm.id,
    'classicalAlgorithm': classicalAlgorithm.id,
    'policy': policy.name,
    'pqcSignature': base64Encode(pqcSignature),
    'classicalSignature': base64Encode(classicalSignature),
  };

  static PqHybridSignature fromJson(Map<String, Object?> json) {
    final version = json['version'] as int? ?? 1;
    if (version != 1) {
      throw PqForgeException('Unsupported hybrid signature version: $version');
    }
    return PqHybridSignature(
      pqcSignature: base64Decode(json['pqcSignature'] as String),
      classicalSignature: base64Decode(json['classicalSignature'] as String),
      pqcAlgorithm: PqSignatureAlgorithm.byId(json['pqcAlgorithm'] as String),
      classicalAlgorithm: PqClassicalSignatureAlgorithm.byId(
        json['classicalAlgorithm'] as String,
      ),
      policy: PqDualSignaturePolicy.values.byName(json['policy'] as String),
    );
  }
}

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
        final ed25519 = crypto.Ed25519();
        final keyPair = seed == null
            ? await ed25519.newKeyPair()
            : await ed25519.newKeyPairFromSeed(seed);
        try {
          final publicKey = await keyPair.extractPublicKey();
          return PqClassicalSignatureKeyPair(
            algorithm: PqClassicalSignatureAlgorithm.ed25519,
            publicKey: Uint8List.fromList(publicKey.bytes),
            secretKey: Uint8List.fromList(
              await keyPair.extractPrivateKeyBytes(),
            ),
          );
        } finally {
          keyPair.destroy();
        }
      case PqClassicalSignatureAlgorithm.ecdsaP256:
        if (seed != null) {
          throw const PqForgeException(
            'Seeded key generation is not supported for ECDSA-P256',
          );
        }
        final pair = PqEcdsaP256.generateKeyPair();
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
  /// ECDSA-P256 it is recomputed as `d · G` via [PqEcdsaP256.publicKeyFromPrivate].
  /// A supplied [publicKey] is used as-is (and length-checked by the key-pair
  /// constructor) without re-derivation.
  Future<PqClassicalSignatureKeyPair> classicalKeyPairFromSecret(
    Uint8List secretKey, {
    Uint8List? publicKey,
  }) async {
    switch (classicalAlgorithm) {
      case PqClassicalSignatureAlgorithm.ed25519:
        final derived = publicKey ?? await _ed25519PublicKeyFromSeed(secretKey);
        return PqClassicalSignatureKeyPair(
          algorithm: PqClassicalSignatureAlgorithm.ed25519,
          publicKey: derived,
          secretKey: secretKey,
        );
      case PqClassicalSignatureAlgorithm.ecdsaP256:
        final derived =
            publicKey ?? PqEcdsaP256.publicKeyFromPrivate(secretKey);
        return PqClassicalSignatureKeyPair(
          algorithm: PqClassicalSignatureAlgorithm.ecdsaP256,
          publicKey: derived,
          secretKey: secretKey,
        );
    }
  }

  static Future<Uint8List> _ed25519PublicKeyFromSeed(Uint8List seed) async {
    final keyPair = await crypto.Ed25519().newKeyPairFromSeed(seed);
    try {
      final publicKey = await keyPair.extractPublicKey();
      return Uint8List.fromList(publicKey.bytes);
    } finally {
      keyPair.destroy();
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
  ) async {
    switch (keyPair.algorithm) {
      case PqClassicalSignatureAlgorithm.ed25519:
        final signature = await crypto.Ed25519().sign(
          boundMessage,
          keyPair: crypto.SimpleKeyPairData(
            keyPair.secretKey,
            publicKey: crypto.SimplePublicKey(
              keyPair.publicKey,
              type: crypto.KeyPairType.ed25519,
            ),
            type: crypto.KeyPairType.ed25519,
          ),
        );
        return Uint8List.fromList(signature.bytes);
      case PqClassicalSignatureAlgorithm.ecdsaP256:
        return PqEcdsaP256.sign(
          privateKey: keyPair.secretKey,
          message: boundMessage,
        );
    }
  }

  static Future<bool> _verifyClassical(
    PqClassicalSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List boundMessage,
    Uint8List signatureBytes,
  ) async {
    switch (algorithm) {
      case PqClassicalSignatureAlgorithm.ed25519:
        if (publicKey.length != 32 || signatureBytes.length != 64) {
          return false;
        }
        return crypto.Ed25519().verify(
          boundMessage,
          signature: crypto.Signature(
            signatureBytes,
            publicKey: crypto.SimplePublicKey(
              publicKey,
              type: crypto.KeyPairType.ed25519,
            ),
          ),
        );
      case PqClassicalSignatureAlgorithm.ecdsaP256:
        return PqEcdsaP256.verify(
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
