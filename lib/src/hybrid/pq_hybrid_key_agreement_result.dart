import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

class PqHybridKeyAgreementResult {
  PqHybridKeyAgreementResult({
    required this.request,
    required Uint8List sessionKey,
  }) : sessionKey = PqBytes.copy(sessionKey);

  final PqHybridKeyAgreementRequest request;
  final Uint8List sessionKey;
}
