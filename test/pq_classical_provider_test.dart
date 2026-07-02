import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

import 'support/classical_conformance.dart';

/// The classical (X25519 / Ed25519 / ECDSA-P256) backend is swappable behind
/// [PqClassicalProvider], so a host can register an FFI-accelerated provider
/// while the pure-Dart implementation remains the default and fallback.
void main() {
  tearDown(
    PqClassical.useDefault,
  ); // never leak a swapped provider between tests

  test('the default classical backend is the pure-Dart provider', () {
    expect(PqClassical.provider, isA<PqPureDartClassicalProvider>());
    expect(PqClassical.provider.name, 'pure-dart-cryptography');
  });

  test(
    'the pure-Dart provider satisfies the classical conformance contract',
    () => classicalProviderConformance(const PqPureDartClassicalProvider()),
  );

  test(
    'the equivalence harness passes a provider against itself',
    () => assertClassicalProvidersAgree(
      const PqPureDartClassicalProvider(),
      const PqPureDartClassicalProvider(),
    ),
  );

  test(
    'registering a provider routes the hybrid classical ops through it',
    () async {
      final spy = _CountingClassicalProvider(
        const PqPureDartClassicalProvider(),
      );
      PqClassical.provider = spy;

      // X25519 shared secret routes through the seam.
      final a = await PqClassical.provider.x25519GenerateKeyPair();
      final b = await PqClassical.provider.x25519GenerateKeyPair();
      final shared = await PqForgeHybridKeyAgreement.x25519SharedSecret(
        secretKey: a.secretKey,
        remotePublicKey: b.publicKey,
      );
      expect(shared, hasLength(32));

      // Ed25519 hybrid sign/verify route through the seam.
      const signer = PqForgeHybridSigner(
        profile: PqForgeProfile.compact,
        classicalAlgorithm: PqClassicalSignatureAlgorithm.ed25519,
      );
      final classicalKeyPair = await signer.generateClassicalKeyPair();
      final pqcKeys = const PqForge(
        profile: PqForgeProfile.compact,
      ).generateKeys();
      final message = Uint8List.fromList(List<int>.generate(20, (i) => i));
      final signature = await signer.sign(
        pqcSecretKey: pqcKeys.signatureKeyPair.secretKey,
        classicalKeyPair: classicalKeyPair,
        message: message,
      );
      final ok = await signer.verify(
        pqcPublicKey: pqcKeys.signatureKeyPair.publicKey,
        classicalPublicKey: classicalKeyPair.publicKey,
        message: message,
        signature: signature,
      );

      expect(ok, isTrue);
      expect(
        spy.x25519Calls,
        greaterThan(0),
        reason: 'X25519 must route through the seam',
      );
      expect(
        spy.ed25519Calls,
        greaterThan(0),
        reason: 'Ed25519 must route through the seam',
      );
    },
  );

  test('the full hybrid handshake (initiate/accept) routes X25519 through '
      'the seam', () async {
    final spy = _CountingClassicalProvider(const PqPureDartClassicalProvider());
    PqClassical.provider = spy;

    const profile = PqForgeProfile.compact;
    final forge = PqForge(profile: profile);
    final serverKem = forge.generateKemKeyPair();
    const agreement = PqForgeHybridKeyAgreement(profile: profile);
    final serverX25519 = await agreement.generateClassicalKeyPair();
    final serverX25519Public = await serverX25519.extractPublicKey();
    final deploymentSalt = Uint8List.fromList(List<int>.filled(32, 7));

    final callsBefore = spy.x25519Calls;
    final client = await agreement.initiate(
      serverClassicalPublicKey: serverX25519Public,
      serverKemPublicKey: serverKem.publicKey,
      deploymentSalt: deploymentSalt,
    );
    final server = await agreement.accept(
      serverClassicalKeyPair: serverX25519,
      serverKemSecretKey: serverKem.secretKey,
      request: client.request,
      deploymentSalt: deploymentSalt,
    );

    expect(
      PqBytes.constantTimeEquals(client.sessionKey, server),
      isTrue,
      reason: 'both peers must derive the same hybrid session key',
    );
    // initiate: ephemeral keygen + ECDH; accept: ECDH => at least 3 seam calls.
    expect(
      spy.x25519Calls - callsBefore,
      greaterThanOrEqualTo(3),
      reason:
          'the ephemeral keygen and both ECDH sides must route through '
          'the seam',
    );
  });
}

/// Forwards to [_inner] and counts how often each family of classical operations
/// was invoked — proof the hybrid layer delegates to the seam.
class _CountingClassicalProvider implements PqClassicalProvider {
  _CountingClassicalProvider(this._inner);

  final PqClassicalProvider _inner;
  int x25519Calls = 0;
  int ed25519Calls = 0;
  int ecdsaCalls = 0;

  @override
  String get name => 'counting(${_inner.name})';

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})> x25519GenerateKeyPair({
    Uint8List? seed,
  }) {
    x25519Calls++;
    return _inner.x25519GenerateKeyPair(seed: seed);
  }

  @override
  Future<Uint8List> x25519SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) {
    x25519Calls++;
    return _inner.x25519SharedSecret(
      secretKey: secretKey,
      remotePublicKey: remotePublicKey,
    );
  }

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})> ed25519GenerateKeyPair({
    Uint8List? seed,
  }) {
    ed25519Calls++;
    return _inner.ed25519GenerateKeyPair(seed: seed);
  }

  @override
  Future<Uint8List> ed25519PublicKeyFromSeed(Uint8List seed) {
    ed25519Calls++;
    return _inner.ed25519PublicKeyFromSeed(seed);
  }

  @override
  Future<Uint8List> ed25519Sign({
    required Uint8List secretKey,
    required Uint8List publicKey,
    required Uint8List message,
  }) {
    ed25519Calls++;
    return _inner.ed25519Sign(
      secretKey: secretKey,
      publicKey: publicKey,
      message: message,
    );
  }

  @override
  Future<bool> ed25519Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    ed25519Calls++;
    return _inner.ed25519Verify(
      publicKey: publicKey,
      message: message,
      signature: signature,
    );
  }

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})>
  ecdsaP256GenerateKeyPair() {
    ecdsaCalls++;
    return _inner.ecdsaP256GenerateKeyPair();
  }

  @override
  Future<Uint8List> ecdsaP256PublicKeyFromPrivate(Uint8List secretKey) {
    ecdsaCalls++;
    return _inner.ecdsaP256PublicKeyFromPrivate(secretKey);
  }

  @override
  Future<Uint8List> ecdsaP256Sign({
    required Uint8List secretKey,
    required Uint8List message,
  }) {
    ecdsaCalls++;
    return _inner.ecdsaP256Sign(secretKey: secretKey, message: message);
  }

  @override
  Future<bool> ecdsaP256Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    ecdsaCalls++;
    return _inner.ecdsaP256Verify(
      publicKey: publicKey,
      message: message,
      signature: signature,
    );
  }
}
