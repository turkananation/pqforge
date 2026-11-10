import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

/// Phase 6: KEM strength and signature strength can be chosen independently
/// (e.g. a maximum KEM with a lighter signature). The custom profile name must
/// round-trip through the envelope binary so the reader reconstructs the same
/// algorithms and key schedule.
void main() {
  test('a decoupled KEM/signature envelope round-trips through binary', () {
    final custom = PqForgeProfile(
      name:
          'custom-${PqKemAlgorithm.mlKem1024.id}-${PqSignatureAlgorithm.mlDsa44.id}',
      kem: PqKemAlgorithm.mlKem1024,
      signature: PqSignatureAlgorithm.mlDsa44,
    );
    const forge = PqForge();
    final recipient = forge.generateKemKeyPair(
      algorithm: PqKemAlgorithm.mlKem1024,
    );
    final signer = forge.generateSignatureKeyPair(
      algorithm: PqSignatureAlgorithm.mlDsa44,
    );
    final message = Uint8List.fromList(
      List<int>.generate(2048, (i) => i & 0xFF),
    );

    final envelope = forge.encrypt(
      recipient.publicKey,
      message,
      profile: custom,
      signerSecretKey: signer.secretKey,
    );
    // Strong KEM, light signature — the decoupling.
    expect(envelope.kemAlgorithm, PqKemAlgorithm.mlKem1024);
    expect(envelope.signatureAlgorithm, PqSignatureAlgorithm.mlDsa44);

    final restored = PqEnvelope.fromBinary(envelope.toBinary());
    expect(restored.kemAlgorithm, PqKemAlgorithm.mlKem1024);
    expect(restored.signatureAlgorithm, PqSignatureAlgorithm.mlDsa44);
    expect(
      forge.decrypt(
        recipient.secretKey,
        restored,
        signerPublicKey: signer.publicKey,
      ),
      message,
    );
  });

  test('a built-in profile name cannot carry a different KEM', () {
    expect(
      () => PqForgeProfile.resolve(
        'balanced',
        PqKemAlgorithm.mlKem1024,
        PqSignatureAlgorithm.mlDsa65,
      ),
      throwsA(isA<PqForgeException>()),
    );
    expect(
      PqForgeProfile.resolve(
        'balanced',
        PqKemAlgorithm.mlKem768,
        PqSignatureAlgorithm.mlDsa65,
      ),
      same(PqForgeProfile.balanced),
    );
    final custom = PqForgeProfile.resolve(
      'custom-${PqKemAlgorithm.mlKem1024.id}-${PqSignatureAlgorithm.mlDsa44.id}',
      PqKemAlgorithm.mlKem1024,
      PqSignatureAlgorithm.mlDsa44,
    );
    expect(custom.kem, PqKemAlgorithm.mlKem1024);
    expect(custom.signature, PqSignatureAlgorithm.mlDsa44);
  });
}
