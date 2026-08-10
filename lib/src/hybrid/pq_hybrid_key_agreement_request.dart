import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqforge/src/exceptions/pqforge_exception.dart';

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
