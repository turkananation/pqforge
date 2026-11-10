/// Opt-in composite signatures: two legs (dual) or three legs (triple).
///
/// Each leg is one algorithm the caller chose. ML-DSA, SLH-DSA, Ed25519,
/// ECDSA-P256, ECDSA-P384, and ECDSA-P521 are peers. None is implied.
/// `hybrid-sign` stays the older ML-DSA + one classical container.
///
/// Every leg signs the same length-prefixed message. A signature from one
/// leg does not verify as another kind of pqforge signature. SLH-DSA `s`
/// sets sign only because the caller passed that key. This is not a
/// constant-time construction, and it is not a FIPS module.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

/// How many legs must verify.
enum PqCompositePolicy {
  requireAll('require-all'),
  acceptAny('accept-any');

  const PqCompositePolicy(this.id);

  final String id;

  static PqCompositePolicy byId(String id) {
    for (final value in values) {
      if (value.id == id || value.name == id) return value;
    }
    throw PqForgeException('Unsupported composite policy: $id');
  }

  bool combine(Iterable<bool> legs) {
    final values = legs.toList();
    if (values.isEmpty) return false;
    return switch (this) {
      PqCompositePolicy.requireAll => values.every((leg) => leg),
      PqCompositePolicy.acceptAny => values.any((leg) => leg),
    };
  }
}

/// One algorithm's signature inside a [PqCompositeSignature].
class PqCompositeLeg {
  PqCompositeLeg({required this.algorithmId, required Uint8List signature})
    : signature = PqBytes.copy(signature);

  final String algorithmId;
  final Uint8List signature;

  Map<String, Object?> toJson() => {
    'algorithm': algorithmId,
    'signature': base64Encode(signature),
  };
}

/// Two or three signatures over one bound message.
class PqCompositeSignature {
  PqCompositeSignature({
    required List<PqCompositeLeg> legs,
    this.policy = PqCompositePolicy.requireAll,
    this.digest = false,
    Uint8List? context,
  }) : context = PqBytes.copy(context ?? Uint8List(0)),
       legs = List.unmodifiable(legs) {
    if (legs.length < 2 || legs.length > 3) {
      throw PqForgeException(
        'A composite signature needs 2 or 3 legs, got ${legs.length}',
      );
    }
    final ids = <String>{};
    for (final leg in legs) {
      if (!ids.add(leg.algorithmId)) {
        throw PqForgeException(
          'Composite legs must use distinct algorithms, duplicate '
          '${leg.algorithmId}',
        );
      }
      requireLength(
        'signature',
        leg.signature,
        compositeSignatureLength(leg.algorithmId),
      );
    }
  }

  final List<PqCompositeLeg> legs;
  final PqCompositePolicy policy;
  final bool digest;
  final Uint8List context;

  Map<String, Object?> toJson() => {
    'version': 1,
    'kind': 'composite',
    'policy': policy.id,
    if (digest) 'digest': 'sha-256',
    if (context.isNotEmpty) 'context': base64Encode(context),
    'legs': [for (final leg in legs) leg.toJson()],
  };

  static PqCompositeSignature fromJson(Map<String, Object?> json) {
    final version = json['version'] as int? ?? 1;
    if (version != 1 || json['kind'] != 'composite') {
      throw PqForgeException(
        'Unsupported composite signature version: $version',
      );
    }
    final rawLegs = json['legs'];
    if (rawLegs is! List) {
      throw const PqForgeException('Composite signature is missing legs');
    }
    final storedContext = json['context'];
    return PqCompositeSignature(
      policy: PqCompositePolicy.byId(
        json['policy'] as String? ?? 'require-all',
      ),
      digest: json['digest'] == 'sha-256',
      context: storedContext is String ? base64Decode(storedContext) : null,
      legs: [
        for (final raw in rawLegs)
          PqCompositeLeg(
            algorithmId: (raw as Map)['algorithm'] as String,
            signature: base64Decode(raw['signature'] as String),
          ),
      ],
    );
  }
}

/// Signs and verifies an explicit set of signature legs.
class PqForgeSignatureComposer {
  const PqForgeSignatureComposer({this.profile = PqForgeProfile.balanced});

  final PqForgeProfile profile;

  Future<PqCompositeSignature> sign({
    required Uint8List message,
    Uint8List? mlDsaSecret,
    PqSignatureAlgorithm? mlDsa,
    Uint8List? slhSecret,
    PqSlhDsaAlgorithm? slhDsa,
    List<PqClassicalSignatureKeyPair> classical = const [],
    PqCompositePolicy policy = PqCompositePolicy.requireAll,
    Uint8List? context,
    bool digest = false,
  }) async {
    if (mlDsaSecret == null && mlDsa != null) {
      throw const PqForgeException('mlDsa requires mlDsaSecret');
    }
    if ((slhSecret == null) != (slhDsa == null)) {
      throw const PqForgeException(
        'Pass slhSecret and slhDsa together, or neither',
      );
    }
    final bound = compositeSignatureMessage(message, context);
    final legs = <PqCompositeLeg>[];
    if (mlDsaSecret != null) {
      final algorithm = mlDsa ?? profile.signature;
      legs.add(
        PqCompositeLeg(
          algorithmId: algorithm.id,
          signature: PqForge(profile: profile).sign(
            mlDsaSecret,
            bound,
            algorithm: algorithm,
            context: PqBytes.utf8Bytes('pqforge/composite-signature/v1'),
          ),
        ),
      );
    }
    if (slhSecret != null && slhDsa != null) {
      legs.add(
        PqCompositeLeg(
          algorithmId: slhDsa.id,
          signature: PqForge(profile: profile).signSlhDsa(
            slhSecret,
            bound,
            algorithm: slhDsa,
            context: PqBytes.utf8Bytes('pqforge/composite-signature/v1'),
            allowSlowSigning: !slhDsa.isFast,
          ),
        ),
      );
    }
    for (final key in classical) {
      legs.add(
        PqCompositeLeg(
          algorithmId: key.algorithm.id,
          signature: await signClassicalLeg(key, bound),
        ),
      );
    }
    return PqCompositeSignature(
      legs: legs,
      policy: policy,
      digest: digest,
      context: context,
    );
  }

  /// Verifies [signature]. [policy] defaults to
  /// [PqCompositePolicy.requireAll] and must equal [PqCompositeSignature.policy].
  /// The signature JSON cannot switch a require-all signature to accept-any.
  Future<bool> verify({
    required Uint8List message,
    required PqCompositeSignature signature,
    Uint8List? mlDsaPublic,
    Uint8List? slhPublic,
    List<({String algorithmId, Uint8List publicKey})> classicalPublic =
        const [],
    PqCompositePolicy policy = PqCompositePolicy.requireAll,
  }) async {
    if (signature.policy != policy) return false;
    final bound = compositeSignatureMessage(message, signature.context);
    final classicalById = {
      for (final key in classicalPublic) key.algorithmId: key.publicKey,
    };
    final results = <bool>[];
    for (final leg in signature.legs) {
      final ml = PqSignatureAlgorithm.tryById(leg.algorithmId);
      if (ml != null) {
        results.add(
          mlDsaPublic != null &&
              PqForge(profile: profile).verify(
                mlDsaPublic,
                bound,
                leg.signature,
                algorithm: ml,
                context: PqBytes.utf8Bytes('pqforge/composite-signature/v1'),
              ),
        );
        continue;
      }
      final slh = PqSlhDsaAlgorithm.tryById(leg.algorithmId);
      if (slh != null) {
        results.add(
          slhPublic != null &&
              PqForge(profile: profile).verifySlhDsa(
                slhPublic,
                bound,
                leg.signature,
                algorithm: slh,
                context: PqBytes.utf8Bytes('pqforge/composite-signature/v1'),
              ),
        );
        continue;
      }
      final publicKey = classicalById[leg.algorithmId];
      if (publicKey == null) {
        results.add(false);
        continue;
      }
      results.add(
        await verifyClassicalLeg(
          PqClassicalSignatureAlgorithm.byId(leg.algorithmId),
          publicKey,
          bound,
          leg.signature,
        ),
      );
    }
    return policy.combine(results);
  }
}

/// Domain-separated message every composite leg signs.
Uint8List compositeSignatureMessage(Uint8List message, Uint8List? context) {
  return PqBytes.lengthPrefixed([
    PqBytes.utf8Bytes('pqforge/composite-signature/v1'),
    context ?? Uint8List(0),
    message,
  ]);
}

/// Raw signature length for an ML-DSA, SLH-DSA, or classical signature id.
int compositeSignatureLength(String algorithmId) {
  final ml = PqSignatureAlgorithm.tryById(algorithmId);
  if (ml != null) return ml.signatureBytes;
  final slh = PqSlhDsaAlgorithm.tryById(algorithmId);
  if (slh != null) return slh.signatureBytes;
  return PqClassicalSignatureAlgorithm.byId(algorithmId).signatureBytes;
}

/// Signs one classical leg. P-256 and Ed25519 use the provider. P-384 and
/// P-521 call the PointyCastle classes directly so a custom provider does
/// not have to grow new methods.
Future<Uint8List> signClassicalLeg(
  PqClassicalSignatureKeyPair key,
  Uint8List message,
) {
  switch (key.algorithm) {
    case PqClassicalSignatureAlgorithm.ed25519:
      return PqClassical.provider.ed25519Sign(
        secretKey: key.secretKey,
        publicKey: key.publicKey,
        message: message,
      );
    case PqClassicalSignatureAlgorithm.ecdsaP256:
      return PqClassical.provider.ecdsaP256Sign(
        secretKey: key.secretKey,
        message: message,
      );
    case PqClassicalSignatureAlgorithm.ecdsaP384:
      return Future.value(
        PqEcdsaP384.sign(privateKey: key.secretKey, message: message),
      );
    case PqClassicalSignatureAlgorithm.ecdsaP521:
      return Future.value(
        PqEcdsaP521.sign(privateKey: key.secretKey, message: message),
      );
  }
}

/// Verifies one classical leg.
Future<bool> verifyClassicalLeg(
  PqClassicalSignatureAlgorithm algorithm,
  Uint8List publicKey,
  Uint8List message,
  Uint8List signature,
) {
  switch (algorithm) {
    case PqClassicalSignatureAlgorithm.ed25519:
      return PqClassical.provider.ed25519Verify(
        publicKey: publicKey,
        message: message,
        signature: signature,
      );
    case PqClassicalSignatureAlgorithm.ecdsaP256:
      return PqClassical.provider.ecdsaP256Verify(
        publicKey: publicKey,
        message: message,
        signature: signature,
      );
    case PqClassicalSignatureAlgorithm.ecdsaP384:
      return Future.value(
        PqEcdsaP384.verify(
          publicKey: publicKey,
          message: message,
          signature: signature,
        ),
      );
    case PqClassicalSignatureAlgorithm.ecdsaP521:
      return Future.value(
        PqEcdsaP521.verify(
          publicKey: publicKey,
          message: message,
          signature: signature,
        ),
      );
  }
}
