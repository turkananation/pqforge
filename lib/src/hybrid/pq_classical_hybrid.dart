/// Batteries-included classical + post-quantum hybrid helpers.
///
/// This file intentionally depends on `package:cryptography`, so it is exported
/// only from `package:pqforge/pqforge.dart`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;

import '../algorithms/pq_algorithms.dart';
import '../primitives/pq_primitives.dart';
import '../recipes/pq_recipes.dart';
import '../services/pqforge_service.dart';
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
  ed25519(id: 'ed25519');

  const PqClassicalSignatureAlgorithm({required this.id});

  final String id;

  static PqClassicalSignatureAlgorithm byId(String id) {
    for (final value in values) {
      if (value.id == id) return value;
    }
    throw PqForgeException('Unsupported classical signature algorithm: $id');
  }
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
    if (this.classicalSignature.isEmpty) {
      throw ArgumentError.value(0, 'classicalSignature', 'must not be empty');
    }
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

  Future<crypto.KeyPair> generateClassicalKeyPair({Uint8List? seed}) {
    final algorithm = _signatureAlgorithm(classicalAlgorithm);
    return seed == null
        ? algorithm.newKeyPair()
        : algorithm.newKeyPairFromSeed(seed);
  }

  Future<PqHybridSignature> sign({
    required Uint8List pqcSecretKey,
    required crypto.KeyPair classicalKeyPair,
    required Uint8List message,
    Uint8List? context,
    PqSignatureAlgorithm? pqcAlgorithm,
    PqDualSignaturePolicy policy = PqDualSignaturePolicy.requireBoth,
  }) async {
    final selectedPqc = pqcAlgorithm ?? profile.signature;
    final boundMessage = _hybridSignatureMessage(message, context);
    final classicalSignature = await _signatureAlgorithm(
      classicalAlgorithm,
    ).sign(boundMessage, keyPair: classicalKeyPair);
    final dual = PqForge(profile: profile).dualSign(
      secretKey: pqcSecretKey,
      message: boundMessage,
      classicalSignature: Uint8List.fromList(classicalSignature.bytes),
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

  Future<bool> verify({
    required Uint8List pqcPublicKey,
    required crypto.PublicKey classicalPublicKey,
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
      boundMessage,
      signature,
      classicalPublicKey,
    );
    return signature.dualSignature.combine(pqcValid, classicalValid);
  }
}

Future<bool> _verifyClassical(
  Uint8List boundMessage,
  PqHybridSignature signature,
  crypto.PublicKey publicKey,
) {
  return _signatureAlgorithm(signature.classicalAlgorithm).verify(
    boundMessage,
    signature: crypto.Signature(
      signature.classicalSignature,
      publicKey: publicKey,
    ),
  );
}

crypto.SignatureAlgorithm _signatureAlgorithm(
  PqClassicalSignatureAlgorithm algorithm,
) {
  return switch (algorithm) {
    PqClassicalSignatureAlgorithm.ed25519 => crypto.Ed25519(),
  };
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
