import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

class PqHybridSignature {
  PqHybridSignature({
    required Uint8List pqcSignature,
    required Uint8List classicalSignature,
    this.pqcAlgorithm,
    this.slhDsa,
    required this.classicalAlgorithm,
    this.policy = PqDualSignaturePolicy.requireBoth,
  }) : pqcSignature = PqBytes.copy(pqcSignature),
       classicalSignature = PqBytes.copy(classicalSignature) {
    if ((pqcAlgorithm == null) == (slhDsa == null)) {
      throw ArgumentError(
        'Pass exactly one of pqcAlgorithm (ML-DSA) or slhDsa (SLH-DSA)',
      );
    }
    requireLength(
      'pqcSignature',
      this.pqcSignature,
      pqcAlgorithm?.signatureBytes ?? slhDsa!.signatureBytes,
    );
    requireLength(
      'classicalSignature',
      this.classicalSignature,
      classicalAlgorithm.signatureBytes,
    );
  }

  final Uint8List pqcSignature;
  final Uint8List classicalSignature;

  /// Set for an ML-DSA post-quantum leg. Version 1 of the JSON.
  final PqSignatureAlgorithm? pqcAlgorithm;

  /// Set for an SLH-DSA post-quantum leg. Version 2 of the JSON.
  final PqSlhDsaAlgorithm? slhDsa;

  final PqClassicalSignatureAlgorithm classicalAlgorithm;
  final PqDualSignaturePolicy policy;

  /// `ml-dsa-65` or `slh-dsa-shake-128f`.
  String get pqcAlgorithmId => slhDsa?.id ?? pqcAlgorithm!.id;

  /// Display name of [pqcAlgorithmId].
  String get pqcAlgorithmName => slhDsa?.name ?? pqcAlgorithm!.name;

  PqDualSignature get dualSignature => PqDualSignature(
    pqcSignature: pqcSignature,
    classicalSignature: classicalSignature,
    policy: policy,
  );

  Map<String, Object?> toJson() => {
    'version': slhDsa == null ? 1 : 2,
    'pqcAlgorithm': pqcAlgorithmId,
    'classicalAlgorithm': classicalAlgorithm.id,
    'policy': policy.name,
    'pqcSignature': base64Encode(pqcSignature),
    'classicalSignature': base64Encode(classicalSignature),
  };

  static PqHybridSignature fromJson(Map<String, Object?> json) {
    final version = json['version'] as int? ?? 1;
    if (version != 1 && version != 2) {
      throw PqForgeException('Unsupported hybrid signature version: $version');
    }
    final id = json['pqcAlgorithm'] as String;
    final slh = version == 2 ? PqSlhDsaAlgorithm.byId(id) : null;
    final ml = version == 1 ? PqSignatureAlgorithm.byId(id) : null;
    return PqHybridSignature(
      pqcSignature: base64Decode(json['pqcSignature'] as String),
      classicalSignature: base64Decode(json['classicalSignature'] as String),
      pqcAlgorithm: ml,
      slhDsa: slh,
      classicalAlgorithm: PqClassicalSignatureAlgorithm.byId(
        json['classicalAlgorithm'] as String,
      ),
      policy: PqDualSignaturePolicy.values.byName(json['policy'] as String),
    );
  }
}
