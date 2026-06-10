/// Conformance + equivalence harness for [PqLatticeProvider] backends.
///
/// Any backend — the built-in pure Dart one or a future FFI binding to a
/// NEON/AVX2 PQClean/liboqs build — must pass [latticeProviderConformance]
/// (cryptographic contract) and, when validated against the reference,
/// [assertProvidersAgree] (byte-level KAT equivalence on the deterministic
/// operations). Import this from a host package's own test to gate a native
/// backend.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

Uint8List _pattern(int length, int Function(int) f) =>
    Uint8List.fromList(List<int>.generate(length, f));

/// Exercises the contract a provider must satisfy on its own: deterministic
/// seeded keygen, deterministic encaps + decaps recovery, and sign/verify
/// round-trip with tamper rejection — across every ML-KEM and ML-DSA parameter.
void latticeProviderConformance(PqLatticeProvider provider) {
  for (final kem in PqKemAlgorithm.values) {
    final seed = _pattern(64, (i) => i & 0xFF);
    final (pk1, sk1) = provider.kemGenerateKeyPair(kem, seed: seed);
    final (pk2, sk2) = provider.kemGenerateKeyPair(kem, seed: seed);
    expect(pk1, pk2, reason: '$kem seeded keygen must be deterministic');
    expect(sk1, sk2);
    expect(pk1, hasLength(kem.publicKeyBytes));
    expect(sk1, hasLength(kem.secretKeyBytes));

    final nonce = _pattern(32, (i) => (i * 7 + 1) & 0xFF);
    final (ct1, ss1) = provider.kemEncapsulate(kem, pk1, nonce: nonce);
    final (ct2, ss2) = provider.kemEncapsulate(kem, pk1, nonce: nonce);
    expect(
      ct1,
      ct2,
      reason: '$kem encaps with a fixed nonce must be deterministic',
    );
    expect(ss1, ss2);
    expect(ct1, hasLength(kem.ciphertextBytes));
    expect(ss1, hasLength(kem.sharedSecretBytes));
    expect(
      provider.kemDecapsulate(kem, sk1, ct1),
      ss1,
      reason: '$kem decaps must recover the encapsulated secret',
    );
  }

  for (final dsa in PqSignatureAlgorithm.values) {
    final seed = _pattern(32, (i) => (i * 3 + 1) & 0xFF);
    final (pk1, sk1) = provider.dsaGenerateKeyPairSeeded(dsa, seed);
    final (pk2, sk2) = provider.dsaGenerateKeyPairSeeded(dsa, seed);
    expect(pk1, pk2, reason: '$dsa seeded keygen must be deterministic');
    expect(sk1, sk2);
    expect(pk1, hasLength(dsa.publicKeyBytes));
    expect(sk1, hasLength(dsa.secretKeyBytes));

    final message = Uint8List.fromList(utf8.encode('conformance/${dsa.id}'));
    for (final preHash in const [false, true]) {
      final signature = provider.dsaSign(dsa, sk1, message, preHash: preHash);
      expect(signature, hasLength(dsa.signatureBytes));
      expect(
        provider.dsaVerify(dsa, pk1, message, signature, preHash: preHash),
        isTrue,
        reason: '$dsa (preHash=$preHash) must verify its own signature',
      );
      final tampered = Uint8List.fromList(message)..[0] ^= 0x01;
      expect(
        provider.dsaVerify(dsa, pk1, tampered, signature, preHash: preHash),
        isFalse,
        reason: '$dsa (preHash=$preHash) must reject a tampered message',
      );
    }
  }
}

/// Asserts [candidate] is byte-equivalent to [reference] on the deterministic
/// operations (KAT equivalence): identical seeded keygen and fixed-nonce
/// encapsulation, mutual decapsulation, and cross-verification of signatures
/// (byte-identity is not required for signing, which may be hedged).
void assertProvidersAgree(
  PqLatticeProvider reference,
  PqLatticeProvider candidate,
) {
  for (final kem in PqKemAlgorithm.values) {
    final seed = _pattern(64, (i) => (i * 5 + 2) & 0xFF);
    final (pkRef, skRef) = reference.kemGenerateKeyPair(kem, seed: seed);
    final (pkCand, skCand) = candidate.kemGenerateKeyPair(kem, seed: seed);
    expect(pkCand, pkRef, reason: '$kem keygen disagrees with the reference');
    expect(skCand, skRef);

    final nonce = _pattern(32, (i) => (i * 11 + 3) & 0xFF);
    final (ctRef, ssRef) = reference.kemEncapsulate(kem, pkRef, nonce: nonce);
    final (ctCand, ssCand) = candidate.kemEncapsulate(
      kem,
      pkCand,
      nonce: nonce,
    );
    expect(ctCand, ctRef, reason: '$kem encaps disagrees with the reference');
    expect(ssCand, ssRef);
    // Each side decapsulates the other's ciphertext to the same secret.
    expect(candidate.kemDecapsulate(kem, skRef, ctRef), ssRef);
    expect(reference.kemDecapsulate(kem, skCand, ctCand), ssCand);
  }

  for (final dsa in PqSignatureAlgorithm.values) {
    final seed = _pattern(32, (i) => (i * 13 + 5) & 0xFF);
    final (pkRef, skRef) = reference.dsaGenerateKeyPairSeeded(dsa, seed);
    final (pkCand, skCand) = candidate.dsaGenerateKeyPairSeeded(dsa, seed);
    expect(pkCand, pkRef, reason: '$dsa keygen disagrees with the reference');
    expect(skCand, skRef);

    final message = Uint8List.fromList(utf8.encode('agreement/${dsa.id}'));
    final sigRef = reference.dsaSign(dsa, skRef, message);
    final sigCand = candidate.dsaSign(dsa, skCand, message);
    expect(
      candidate.dsaVerify(dsa, pkRef, message, sigRef),
      isTrue,
      reason: '$dsa candidate cannot verify a reference signature',
    );
    expect(
      reference.dsaVerify(dsa, pkCand, message, sigCand),
      isTrue,
      reason: '$dsa reference cannot verify a candidate signature',
    );
  }
}
