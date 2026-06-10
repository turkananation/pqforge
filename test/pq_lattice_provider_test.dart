import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

import 'support/lattice_conformance.dart';

/// Phase 7: the lattice (ML-KEM / ML-DSA) backend is swappable behind
/// [PqLatticeProvider], so a host can register an FFI-accelerated provider while
/// the pure-Dart implementation remains the default and fallback.
void main() {
  tearDown(PqLattice.useDefault); // never leak a swapped provider between tests

  test('the default backend is the pure-Dart provider', () {
    expect(PqLattice.provider, isA<PqPureDartLatticeProvider>());
    expect(PqLattice.provider.name, 'pure-dart-pqcrypto');
  });

  test(
    'the pure-Dart provider satisfies the lattice conformance contract',
    () => latticeProviderConformance(const PqPureDartLatticeProvider()),
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'the KAT-equivalence harness passes a provider against itself',
    () => assertProvidersAgree(
      const PqPureDartLatticeProvider(),
      const PqPureDartLatticeProvider(),
    ),
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test('registering a provider routes the primitives through it', () {
    final spy = _CountingProvider(const PqPureDartLatticeProvider());
    PqLattice.provider = spy;

    const forge = PqForge(profile: PqForgeProfile.compact);
    final keys = forge.generateKeys();
    final envelope = forge.encrypt(
      keys.kemKeyPair.publicKey,
      Uint8List(16),
      signerSecretKey: keys.signatureKeyPair.secretKey,
    );
    final opened = forge.decrypt(
      keys.kemKeyPair.secretKey,
      envelope,
      signerPublicKey: keys.signatureKeyPair.publicKey,
    );

    expect(opened, Uint8List(16));
    expect(
      spy.kemCalls,
      greaterThan(0),
      reason: 'KEM must route through the seam',
    );
    expect(
      spy.dsaCalls,
      greaterThan(0),
      reason: 'DSA must route through the seam',
    );
  });
}

/// A decorator that forwards to [_inner] and counts how often each family of
/// lattice operations was invoked — proof the primitives delegate to the seam.
class _CountingProvider implements PqLatticeProvider {
  _CountingProvider(this._inner);

  final PqLatticeProvider _inner;
  int kemCalls = 0;
  int dsaCalls = 0;

  @override
  String get name => 'counting(${_inner.name})';

  @override
  (Uint8List, Uint8List) kemGenerateKeyPair(
    PqKemAlgorithm algorithm, {
    Uint8List? seed,
  }) {
    kemCalls++;
    return _inner.kemGenerateKeyPair(algorithm, seed: seed);
  }

  @override
  (Uint8List, Uint8List) kemEncapsulate(
    PqKemAlgorithm algorithm,
    Uint8List publicKey, {
    Uint8List? nonce,
  }) {
    kemCalls++;
    return _inner.kemEncapsulate(algorithm, publicKey, nonce: nonce);
  }

  @override
  Uint8List kemDecapsulate(
    PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) {
    kemCalls++;
    return _inner.kemDecapsulate(algorithm, secretKey, ciphertext);
  }

  @override
  (Uint8List, Uint8List) dsaGenerateKeyPair(PqSignatureAlgorithm algorithm) {
    dsaCalls++;
    return _inner.dsaGenerateKeyPair(algorithm);
  }

  @override
  (Uint8List, Uint8List) dsaGenerateKeyPairSeeded(
    PqSignatureAlgorithm algorithm,
    Uint8List seed,
  ) {
    dsaCalls++;
    return _inner.dsaGenerateKeyPairSeeded(algorithm, seed);
  }

  @override
  Uint8List dsaSign(
    PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? context,
    bool preHash = false,
  }) {
    dsaCalls++;
    return _inner.dsaSign(
      algorithm,
      secretKey,
      message,
      context: context,
      preHash: preHash,
    );
  }

  @override
  bool dsaVerify(
    PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
    bool preHash = false,
  }) {
    dsaCalls++;
    return _inner.dsaVerify(
      algorithm,
      publicKey,
      message,
      signature,
      context: context,
      preHash: preHash,
    );
  }
}
