import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

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
