import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/export.dart' as pc;
// The cryptography entrypoint re-exports the zero-dependency core, so both
// Option A (PqForgeCombiner / PqHybridProfile) and Option B (the SecretKey
// extension) are visible from this single import.
import 'package:pqforge/pqforge_cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('PqForgeCombiner core (Option A)', () {
    test('matches RFC 5869 Test Case 1 (HKDF-SHA-256) across the join', () {
      // RFC 5869 Appendix A.1: IKM = 22 x 0x0b. We split it so that
      // classical || post-quantum reconstructs the canonical IKM, proving both
      // the concatenation order and the HKDF wiring against an external vector.
      final classical = Uint8List.fromList(List<int>.filled(11, 0x0b));
      final postQuantum = Uint8List.fromList(List<int>.filled(11, 0x0b));
      final salt = _hex('000102030405060708090a0b0c');
      final info = _hex('f0f1f2f3f4f5f6f7f8f9');
      final expectedOkm = _hex(
        '3cb25f25faacd57a90434f64d0362f2a'
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
      );

      final derived = const PqForgeCombiner.balanced().combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: info,
        salt: salt,
        length: 42,
      );

      expect(derived, orderedEquals(expectedOkm));
    });

    test('is deterministic for identical inputs (both profiles)', () {
      for (final profile in PqHybridProfile.values) {
        final combiner = PqForgeCombiner(profile: profile);
        final a = combiner.combine(
          classicalSharedSecret: _filled(32, 7),
          postQuantumSharedSecret: _filled(32, 9),
          info: _bytes('pqforge/test/v1'),
          salt: _filled(16, 3),
        );
        final b = combiner.combine(
          classicalSharedSecret: _filled(32, 7),
          postQuantumSharedSecret: _filled(32, 9),
          info: _bytes('pqforge/test/v1'),
          salt: _filled(16, 3),
        );
        expect(
          a,
          orderedEquals(b),
          reason: '${profile.name} not deterministic',
        );
        expect(a, hasLength(PqForgeCombiner.defaultLength));
      }
    });

    test('enforces IETF ordering: swapping the shares changes the key', () {
      const combiner = PqForgeCombiner.balanced();
      final classical = _filled(32, 1);
      final postQuantum = _filled(32, 2);
      final info = _bytes('pqforge/order/v1');

      final forward = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: info,
      );
      final swapped = combiner.combine(
        classicalSharedSecret: postQuantum,
        postQuantumSharedSecret: classical,
        info: info,
      );

      expect(forward, isNot(orderedEquals(swapped)));
    });

    test('balanced (SHA-256) and heavy (SHA-512) profiles diverge', () {
      final args = {
        'classicalSharedSecret': _filled(32, 4),
        'postQuantumSharedSecret': _filled(32, 5),
      };
      final balanced = const PqForgeCombiner.balanced().combine(
        classicalSharedSecret: args['classicalSharedSecret']!,
        postQuantumSharedSecret: args['postQuantumSharedSecret']!,
        info: _bytes('pqforge/profile/v1'),
      );
      final heavy = const PqForgeCombiner.heavy().combine(
        classicalSharedSecret: args['classicalSharedSecret']!,
        postQuantumSharedSecret: args['postQuantumSharedSecret']!,
        info: _bytes('pqforge/profile/v1'),
      );
      expect(balanced, isNot(orderedEquals(heavy)));
    });

    test('domain-separation info binds the output and is mandatory', () {
      const combiner = PqForgeCombiner.balanced();
      final classical = _filled(32, 6);
      final postQuantum = _filled(32, 8);

      final clientKey = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: _bytes('pqforge/session/v1/client'),
      );
      final serverKey = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: _bytes('pqforge/session/v1/server'),
      );
      expect(clientKey, isNot(orderedEquals(serverKey)));

      expect(
        () => combiner.combine(
          classicalSharedSecret: classical,
          postQuantumSharedSecret: postQuantum,
          info: Uint8List(0),
        ),
        throwsArgumentError,
      );
    });

    test('salt binds the output; null and empty salt are equivalent', () {
      const combiner = PqForgeCombiner.balanced();
      final classical = _filled(32, 10);
      final postQuantum = _filled(32, 11);
      final info = _bytes('pqforge/salt/v1');

      final saltedA = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: info,
        salt: _filled(16, 1),
      );
      final saltedB = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: info,
        salt: _filled(16, 2),
      );
      expect(saltedA, isNot(orderedEquals(saltedB)));

      // RFC 5869: a missing salt and an empty salt both fall back to HashLen
      // zero bytes, so they must derive the same key.
      final nullSalt = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: info,
      );
      final emptySalt = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: info,
        salt: Uint8List(0),
      );
      expect(nullSalt, orderedEquals(emptySalt));
    });

    test('respects custom output length and its profile-bound ceiling', () {
      const combiner = PqForgeCombiner.balanced();
      final classical = _filled(32, 12);
      final postQuantum = _filled(32, 13);
      final info = _bytes('pqforge/length/v1');

      final long = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: info,
        length: 64,
      );
      expect(long, hasLength(64));
      // The first 32 bytes are independent of the requested length under HKDF.
      final short = combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: info,
        length: 32,
      );
      expect(long.sublist(0, 32), orderedEquals(short));

      // SHA-256 HKDF can emit at most 255 * 32 = 8160 bytes.
      expect(
        () => combiner.combine(
          classicalSharedSecret: classical,
          postQuantumSharedSecret: postQuantum,
          info: info,
          length: 255 * 32 + 1,
        ),
        throwsRangeError,
      );
      expect(
        () => combiner.combine(
          classicalSharedSecret: classical,
          postQuantumSharedSecret: postQuantum,
          info: info,
          length: 0,
        ),
        throwsRangeError,
      );
    });

    test('rejects empty shared secrets', () {
      const combiner = PqForgeCombiner.balanced();
      expect(
        () => combiner.combine(
          classicalSharedSecret: Uint8List(0),
          postQuantumSharedSecret: _filled(32, 1),
          info: _bytes('x'),
        ),
        throwsArgumentError,
      );
      expect(
        () => combiner.combine(
          classicalSharedSecret: _filled(32, 1),
          postQuantumSharedSecret: Uint8List(0),
          info: _bytes('x'),
        ),
        throwsArgumentError,
      );
    });

    test('combine does not mutate its input secrets', () {
      const combiner = PqForgeCombiner.balanced();
      final classical = _filled(32, 21);
      final postQuantum = _filled(32, 22);
      combiner.combine(
        classicalSharedSecret: classical,
        postQuantumSharedSecret: postQuantum,
        info: _bytes('pqforge/immutability/v1'),
      );
      expect(classical, orderedEquals(_filled(32, 21)));
      expect(postQuantum, orderedEquals(_filled(32, 22)));
    });

    test('wipe zeroizes a buffer in place', () {
      final buffer = _filled(48, 0xAA);
      PqForgeCombiner.wipe(buffer);
      expect(buffer, everyElement(0));
      expect(buffer, hasLength(48));
    });
  });

  group('PqForgeCryptographyExtensions (Option B)', () {
    test('derives a session key of the requested length', () async {
      final classical = crypto.SecretKey(_filled(32, 30));
      final postQuantum = crypto.SecretKey(_filled(32, 31));

      final session = await classical.deriveHybridSecretKey(
        postQuantumSecret: postQuantum,
        info: _bytes('pqforge/ext/v1'),
        length: 48,
      );

      expect(await session.extractBytes(), hasLength(48));
    });

    test(
      'leaves the input secret keys intact (no caller-buffer wipe)',
      () async {
        final classicalBytes = _filled(32, 40);
        final postQuantumBytes = _filled(32, 41);
        final classical = crypto.SecretKey(classicalBytes);
        final postQuantum = crypto.SecretKey(postQuantumBytes);

        await classical.deriveHybridSecretKey(
          postQuantumSecret: postQuantum,
          info: _bytes('pqforge/ext/intact/v1'),
        );

        expect(await classical.extractBytes(), orderedEquals(_filled(32, 40)));
        expect(
          await postQuantum.extractBytes(),
          orderedEquals(_filled(32, 41)),
        );
      },
    );

    test('propagates empty-info rejection from the core', () {
      final classical = crypto.SecretKey(_filled(32, 50));
      final postQuantum = crypto.SecretKey(_filled(32, 51));
      expect(
        () => classical.deriveHybridSecretKey(
          postQuantumSecret: postQuantum,
          info: Uint8List(0),
        ),
        throwsArgumentError,
      );
    });
  });

  group('cross-path equivalence (Option A == Option B)', () {
    // The headline guarantee: identical raw entropy must yield identical
    // symmetric session state regardless of which entry strategy is used.
    final classicalBytes = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final postQuantumBytes = Uint8List.fromList(
      List<int>.generate(32, (i) => 255 - i),
    );

    for (final profile in PqHybridProfile.values) {
      test('paths agree for the ${profile.name} profile', () async {
        final info = _bytes('pqforge/cross-path/v1');
        final salt = _filled(24, 0x5a);
        const length = 44;

        final corePath = PqForgeCombiner(profile: profile).combine(
          classicalSharedSecret: Uint8List.fromList(classicalBytes),
          postQuantumSharedSecret: Uint8List.fromList(postQuantumBytes),
          info: info,
          salt: salt,
          length: length,
        );

        final extPath =
            await crypto.SecretKey(
              Uint8List.fromList(classicalBytes),
            ).deriveHybridSecretKey(
              postQuantumSecret: crypto.SecretKey(
                Uint8List.fromList(postQuantumBytes),
              ),
              info: info,
              salt: salt,
              profile: profile,
              length: length,
            );
        final extBytes = await extPath.extractBytes();

        expect(extBytes, orderedEquals(corePath));
      });
    }

    test('both paths track an independent PointyCastle reference', () async {
      final info = _bytes('pqforge/reference/v1');
      final salt = _filled(16, 0x33);
      final reference = _referenceHkdf(
        digest: pc.SHA256Digest(),
        ikm: _concat(classicalBytes, postQuantumBytes),
        salt: salt,
        info: info,
        length: 32,
      );

      final corePath = const PqForgeCombiner.balanced().combine(
        classicalSharedSecret: Uint8List.fromList(classicalBytes),
        postQuantumSharedSecret: Uint8List.fromList(postQuantumBytes),
        info: info,
        salt: salt,
      );
      final extPath = await crypto.SecretKey(Uint8List.fromList(classicalBytes))
          .deriveHybridSecretKey(
            postQuantumSecret: crypto.SecretKey(
              Uint8List.fromList(postQuantumBytes),
            ),
            info: info,
            salt: salt,
          );

      expect(corePath, orderedEquals(reference));
      expect(await extPath.extractBytes(), orderedEquals(reference));
    });
  });
}

/// Independent RFC 5869 HKDF computed directly with PointyCastle, used to
/// cross-check the combiner without reusing its code path.
Uint8List _referenceHkdf({
  required pc.Digest digest,
  required Uint8List ikm,
  required Uint8List info,
  required int length,
  Uint8List? salt,
}) {
  final derivator = pc.HKDFKeyDerivator(digest)
    ..init(pc.HkdfParameters(ikm, length, salt, info));
  final out = Uint8List(length);
  derivator.deriveKey(null, 0, out, 0);
  return out;
}

Uint8List _concat(Uint8List a, Uint8List b) => Uint8List(a.length + b.length)
  ..setRange(0, a.length, a)
  ..setRange(a.length, a.length + b.length, b);

Uint8List _filled(int length, int value) =>
    Uint8List.fromList(List<int>.filled(length, value));

Uint8List _bytes(String value) => Uint8List.fromList(utf8.encode(value));

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
