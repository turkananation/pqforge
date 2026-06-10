import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

/// F4: the FIPS deployment policy. Algorithms were already the approved set;
/// these tests pin the two runtime restrictions (AES-GCM-only suites,
/// PBKDF2-only key wrapping), the PBKDF2 wrap round-trip, and the swappable
/// randomness source for module-DRBG deployments.
void main() {
  tearDown(() {
    PqFipsMode.disable();
    PqRandom.useDefault();
  });

  group('PBKDF2 key wrapping (FIPS-approved KDF)', () {
    const forge = PqForge();
    final key = PqExportedKey(
      kind: PqKeyKind.kemSecret,
      algorithmId: PqKemAlgorithm.mlKem512.id,
      keyId: 'wrap-test',
      bytes: Uint8List.fromList(List<int>.generate(64, (i) => i)),
    );

    test('wraps and unwraps under pbkdf2-hmac-sha256', () {
      final wrapped = forge.wrapKeyWithPassphrase(
        key,
        'correct horse battery staple',
        kdf: PqKdf.pbkdf2HmacSha256,
        pbkdf2Iterations: 1000, // keep the test fast; default is 600k
      );
      expect(wrapped.kdf, PqKdf.pbkdf2HmacSha256);
      expect(wrapped.iterations, 1000);

      // Survives JSON (the on-disk wrapped-key form).
      final restored = PqWrappedKey.fromJson(wrapped.toJson());
      final unwrapped = forge.unwrapKeyWithPassphrase(
        restored,
        'correct horse battery staple',
      );
      expect(unwrapped.bytes, key.bytes);
      expect(unwrapped.kind, key.kind);
    });

    test('a wrong passphrase fails the AEAD, not silently', () {
      final wrapped = forge.wrapKeyWithPassphrase(
        key,
        'right',
        kdf: PqKdf.pbkdf2HmacSha256,
        pbkdf2Iterations: 1000,
      );
      expect(
        () => forge.unwrapKeyWithPassphrase(wrapped, 'wrong'),
        throwsA(anything),
      );
    });

    test('argon2id remains the default outside FIPS mode', () {
      final wrapped = forge.wrapKeyWithPassphrase(key, 'pw');
      expect(wrapped.kdf, PqKdf.argon2id);
      expect(forge.unwrapKeyWithPassphrase(wrapped, 'pw').bytes, key.bytes);
    });
  });

  group('PqFipsMode enforcement', () {
    const forge = PqForge();
    final key = PqExportedKey(
      kind: PqKeyKind.kemSecret,
      algorithmId: PqKemAlgorithm.mlKem512.id,
      bytes: Uint8List(32),
    );

    test('forbids Argon2id wrapping and unwrapping when enabled', () {
      final argonWrapped = forge.wrapKeyWithPassphrase(key, 'pw');
      PqFipsMode.enable();
      expect(
        () => forge.wrapKeyWithPassphrase(key, 'pw'),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        () => forge.unwrapKeyWithPassphrase(argonWrapped, 'pw'),
        throwsA(isA<PqForgeException>()),
      );
      // The approved KDF still works.
      final wrapped = forge.wrapKeyWithPassphrase(
        key,
        'pw',
        kdf: PqKdf.pbkdf2HmacSha256,
        pbkdf2Iterations: 1000,
      );
      expect(forge.unwrapKeyWithPassphrase(wrapped, 'pw').bytes, key.bytes);
    });

    test('forbids ChaCha20-Poly1305 sessions when enabled', () {
      PqFipsMode.enable();
      expect(
        () => PqForgeSecureSession(
          secretKey: Uint8List(32),
          cipherSuite: PqForgeCipherSuite.chaCha20Poly1305,
        ),
        throwsA(isA<PqForgeException>()),
      );
      // AES-256-GCM still constructs.
      PqForgeSecureSession(
        secretKey: Uint8List(32),
        cipherSuite: PqForgeCipherSuite.aes256Gcm,
      ).dispose();
    });

    test('forbids a ChaCha20-Poly1305 streaming cipher when enabled', () {
      PqFipsMode.enable();
      expect(
        () => PqForgeStreamCipher.forProvider(
          PqForgeEngineProvider.nativeCryptography,
          cipherSuite: PqForgeCipherSuite.chaCha20Poly1305,
        ),
        throwsA(isA<PqForgeException>()),
      );
      PqForgeStreamCipher(); // default AES-256-GCM still constructs
    });
  });

  group('PqRandom (module DRBG hook)', () {
    test('a registered generator supplies all randomness', () {
      var calls = 0;
      PqRandom.generator = (length) {
        calls++;
        return Uint8List.fromList(List<int>.filled(length, 0x42));
      };
      final bytes = PqBytes.randomBytes(16);
      expect(bytes, everyElement(0x42));
      expect(calls, 1);
    });

    test('a generator returning the wrong length is rejected', () {
      PqRandom.generator = (length) => Uint8List(length + 1);
      expect(() => PqBytes.randomBytes(8), throwsStateError);
    });
  });
}
