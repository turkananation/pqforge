/// Regression tests for the Argon2id parameter bounds.
///
/// The defect: `iterations`, `memoryPowerOf2` and `lanes` reached
/// `pc.Argon2Parameters` and `generator.process()` with no range check, while
/// the adjacent `pbkdf2Sha256` validated its own `iterations`. Because a
/// `PqWrappedKey` round-trips through JSON, those parameters are part of the
/// untrusted input to `unwrapKeyWithPassphrase`. A stored record claiming
/// `memoryPowerOf2: 30` requested 1 GiB of allocation before any
/// authentication happened.
///
/// These tests assert the rejection happens *before* the derivation runs, which
/// is the property that matters — a RangeError thrown after allocation would not
/// fix anything.
library;

import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

/// A passphrase-protected key used as the round-trip fixture.
PqWrappedKey _wrapFixture({String passphrase = 'correct horse battery'}) {
  const forge = PqForge();
  final wrapped = forge.wrapKeyWithPassphrase(
    PqExportedKey(
      kind: PqKeyKind.kemSecret,
      algorithmId: 'ml-kem-768',
      bytes: Uint8List(32),
      keyId: 'argon2-bounds-fixture',
    ),
    passphrase,
    // Cheapest legal parameters: these tests assert rejection, not KDF output.
    iterations: 1,
    memoryPowerOf2: 10,
    lanes: 1,
  );
  return wrapped;
}

/// Returns [wrapped] with one cost field replaced, keeping everything else.
PqWrappedKey _withCost(
  PqWrappedKey wrapped, {
  int? iterations,
  int? memoryPowerOf2,
  int? lanes,
  Uint8List? salt,
}) => PqWrappedKey(
  kdf: wrapped.kdf,
  aead: wrapped.aead,
  salt: salt ?? wrapped.salt,
  nonce: wrapped.nonce,
  ciphertext: wrapped.ciphertext,
  keyKind: wrapped.keyKind,
  algorithmId: wrapped.algorithmId,
  keyId: wrapped.keyId,
  iterations: iterations ?? wrapped.iterations,
  memoryPowerOf2: memoryPowerOf2 ?? wrapped.memoryPowerOf2,
  lanes: lanes ?? wrapped.lanes,
);

void main() {
  group('Argon2Limits — declared bounds', () {
    test('the upper memory bound is 1 GiB, not unbounded', () {
      // 2^20 KiB. This is the whole point of the fix: a hostile record cannot
      // ask for more than 1 GiB in a single derivation.
      expect(Argon2Limits.maxArgon2MemoryPowerOf2, 20);
      expect(
        1 << Argon2Limits.maxArgon2MemoryPowerOf2,
        1024 * 1024,
        reason: '2^20 KiB must equal 1 GiB',
      );
    });

    test('bounds are ordered so every range is non-empty', () {
      expect(
        Argon2Limits.minArgon2Iterations,
        lessThanOrEqualTo(Argon2Limits.maxArgon2Iterations),
      );
      expect(
        Argon2Limits.minArgon2MemoryPowerOf2,
        lessThanOrEqualTo(Argon2Limits.maxArgon2MemoryPowerOf2),
      );
      expect(
        Argon2Limits.minArgon2Lanes,
        lessThanOrEqualTo(Argon2Limits.maxArgon2Lanes),
      );
      expect(Argon2Limits.minArgon2SaltBytes, greaterThan(0));
    });
  });

  group('PqSymmetricPrimitives.argon2id — rejects out-of-range cost', () {
    test('memoryPowerOf2 above the ceiling is refused', () {
      expect(
        () => PqSymmetricPrimitives.argon2id(
          password: 'pw',
          salt: Uint8List.fromList(List<int>.filled(16, 7)),
          iterations: 1,
          memoryPowerOf2: Argon2Limits.maxArgon2MemoryPowerOf2 + 1,
          lanes: 1,
        ),
        throwsA(isA<RangeError>()),
      );
    });

    test('memoryPowerOf2: 40 would request a terabyte and is refused', () {
      expect(
        () => PqSymmetricPrimitives.argon2id(
          password: 'pw',
          salt: Uint8List.fromList(List<int>.filled(16, 7)),
          iterations: 1,
          memoryPowerOf2: 40,
          lanes: 1,
        ),
        throwsA(isA<RangeError>()),
      );
    });

    test('memoryPowerOf2 below the floor is refused', () {
      expect(
        () => PqSymmetricPrimitives.argon2id(
          password: 'pw',
          salt: Uint8List.fromList(List<int>.filled(16, 7)),
          iterations: 1,
          memoryPowerOf2: Argon2Limits.minArgon2MemoryPowerOf2 - 1,
          lanes: 1,
        ),
        throwsA(isA<RangeError>()),
      );
    });

    test('zero and negative iterations are refused', () {
      for (final bad in <int>[0, -1, Argon2Limits.maxArgon2Iterations + 1]) {
        expect(
          () => PqSymmetricPrimitives.argon2id(
            password: 'pw',
            salt: Uint8List.fromList(List<int>.filled(16, 7)),
            iterations: bad,
            memoryPowerOf2: 10,
            lanes: 1,
          ),
          throwsA(isA<RangeError>()),
          reason: 'iterations: $bad must be refused',
        );
      }
    });

    test('zero and excessive lanes are refused', () {
      for (final bad in <int>[0, -1, Argon2Limits.maxArgon2Lanes + 1]) {
        expect(
          () => PqSymmetricPrimitives.argon2id(
            password: 'pw',
            salt: Uint8List.fromList(List<int>.filled(16, 7)),
            iterations: 1,
            memoryPowerOf2: 10,
            lanes: bad,
          ),
          throwsA(isA<RangeError>()),
          reason: 'lanes: $bad must be refused',
        );
      }
    });

    test('a salt below the minimum is refused', () {
      expect(
        () => PqSymmetricPrimitives.argon2id(
          password: 'pw',
          salt: Uint8List(Argon2Limits.minArgon2SaltBytes - 1),
          iterations: 1,
          memoryPowerOf2: 10,
          lanes: 1,
        ),
        throwsA(isA<RangeError>()),
      );
      expect(
        () => PqSymmetricPrimitives.argon2id(
          password: 'pw',
          salt: Uint8List(0),
          iterations: 1,
          memoryPowerOf2: 10,
          lanes: 1,
        ),
        throwsA(isA<RangeError>()),
      );
    });

    test('legal extremes still derive a key', () {
      final salt = Uint8List.fromList(List<int>.filled(16, 3));
      for (final m in <int>[
        Argon2Limits.minArgon2MemoryPowerOf2,
        Argon2Limits.maxArgon2MemoryPowerOf2,
      ]) {
        final key = PqSymmetricPrimitives.argon2id(
          password: 'pw',
          salt: salt,
          iterations: Argon2Limits.maxArgon2Iterations,
          memoryPowerOf2: m,
          lanes: 1,
        );
        expect(key.length, greaterThan(0));
      }
    }, tags: 'slow');
  });

  group('unwrapKeyWithPassphrase — rejects a hostile record cost', () {
    test('a stored memoryPowerOf2 of 30 is refused as a PqForgeException', () {
      final hostile = _withCost(_wrapFixture(), memoryPowerOf2: 30);

      expect(
        () =>
            const PqForge().unwrapKeyWithPassphrase(hostile, 'any passphrase'),
        throwsA(isA<PqForgeException>()),
      );
    });

    test('the message names the field, the observed value and the range', () {
      final hostile = _withCost(_wrapFixture(), memoryPowerOf2: 30);

      Object? caught;
      try {
        const PqForge().unwrapKeyWithPassphrase(hostile, 'any passphrase');
      } catch (e) {
        caught = e;
      }

      expect(caught, isA<PqForgeException>());
      final message = caught.toString();
      expect(message, contains('memoryPowerOf2'));
      expect(message, contains('30'));
      expect(
        message,
        contains(
          '${Argon2Limits.minArgon2MemoryPowerOf2}..${Argon2Limits.maxArgon2MemoryPowerOf2}',
        ),
      );
    });

    test('excessive iterations and lanes are refused', () {
      for (final hostile in <PqWrappedKey>[
        _withCost(_wrapFixture(), iterations: 100000),
        _withCost(_wrapFixture(), lanes: 4096),
      ]) {
        expect(
          () => const PqForge().unwrapKeyWithPassphrase(hostile, 'pw'),
          throwsA(isA<PqForgeException>()),
        );
      }
    });

    test('a short salt is refused', () {
      final hostile = _withCost(
        _wrapFixture(),
        salt: Uint8List(Argon2Limits.minArgon2SaltBytes - 1),
      );

      expect(
        () => const PqForge().unwrapKeyWithPassphrase(hostile, 'pw'),
        throwsA(isA<PqForgeException>()),
      );
    });

    test('the rejection is not a RangeError leaking out of the service', () {
      // The service-level guard must produce a typed PqForgeException so
      // callers can distinguish "this record is malformed" from "this
      // passphrase was wrong".
      final hostile = _withCost(_wrapFixture(), memoryPowerOf2: 30);

      Object? caught;
      try {
        const PqForge().unwrapKeyWithPassphrase(hostile, 'pw');
      } catch (e) {
        caught = e;
      }

      expect(caught, isNot(isA<RangeError>()));
      expect(caught, isA<PqForgeException>());
    });

    test('a legitimate record still unwraps', () {
      const forge = PqForge();
      final wrapped = _wrapFixture();
      final restored = forge.unwrapKeyWithPassphrase(
        wrapped,
        'correct horse battery',
      );

      expect(restored.bytes.length, 32);
    });

    test('a wrong passphrase is distinguishable from a malformed record', () {
      // The distinction a caller actually needs:
      //   malformed cost  -> PqForgeException (this guard)
      //   wrong passphrase -> AEAD tag failure
      // These must not be conflated. A caller retrying on a transient failure
      // must not treat a corrupt record as a typo.
      final wrapped = _wrapFixture();

      expect(
        () => const PqForge().unwrapKeyWithPassphrase(
          wrapped,
          'wrong passphrase',
        ),
        throwsA(isNot(isA<PqForgeException>())),
        reason:
            'a wrong passphrase fails at AEAD verification, not at the '
            'cost guard',
      );

      expect(
        () => const PqForge().unwrapKeyWithPassphrase(
          _withCost(wrapped, memoryPowerOf2: 30),
          'correct horse battery',
        ),
        throwsA(isA<PqForgeException>()),
        reason: 'a malformed cost is rejected before any derivation',
      );
    });
  });

  group('PQTH / PBKDF2 cost is unaffected', () {
    test('the pbkdf2 path keeps its own separate bound', () {
      // pbkdf2Sha256 validated its iterations before this change; confirm the
      // Argon2id guard did not accidentally narrow or widen it.
      expect(
        () => PqSymmetricPrimitives.pbkdf2Sha256(
          password: 'pw',
          salt: Uint8List.fromList(List<int>.filled(16, 1)),
          iterations: 0,
        ),
        throwsA(isA<RangeError>()),
      );
    });
  });
}
