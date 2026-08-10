import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqforge/src/hybrid/pq_hybrid_key_agreement_request.dart';

class PqHybridKeyAgreementResult {
  PqHybridKeyAgreementResult({
    required this.request,
    required Uint8List sessionKey,
  }) : sessionKey = PqBytes.copy(sessionKey);

  final PqHybridKeyAgreementRequest request;
  final Uint8List sessionKey;
}
