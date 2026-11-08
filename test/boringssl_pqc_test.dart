/// BoringSSL 0.20261020 against the pqcrypto bytes pqforge pins.
///
/// This pin does not export ML-KEM-512 or ten of the twelve SLH-DSA sets.
/// Those stay on the OpenSSL suite. What it does export is checked here:
/// ML-KEM-768 and ML-KEM-1024, ML-DSA-44/65/87, SLH-DSA SHA2-128s and
/// SHAKE-256f.
///
/// Public keys from the same seed must match. Encapsulation and signatures
/// are cross-checked, not required to be byte-identical: BoringSSL draws its
/// own coins. The driver is tool/interop/boringssl_pqc, built by
/// tool/interop/build_pinned.sh. A missing binary skips, unless
/// REQUIRE_PINNED_TLS=1, in which case it fails.
@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

void main() {
  final binary = File('tool/interop/.build/boringssl/bin/boringssl_pqc');
  final required = Platform.environment['REQUIRE_PINNED_TLS'] == '1';
  if (!binary.existsSync()) {
    test('BoringSSL PQC interop', () {
      if (required) {
        fail('pinned boringssl_pqc was not built');
      }
    }, skip: required ? false : 'pinned BoringSSL driver is not built');
    return;
  }

  final bin = binary.path;
  final message = Uint8List.fromList('pqforge'.codeUnits);
  final context = Uint8List(0);

  group('ML-KEM', () {
    for (final level in const ['768', '1024']) {
      final kem = level == '768' ? PqcKem.kyber768 : PqcKem.kyber1024;
      test('ML-KEM-$level seed and both directions', () {
        final seed = _fill(64, 0x11);
        final ours = kem.generateKeyPair(seed);
        final theirs = _hex(_run(bin, ['kem-public', level, _hexText(seed)]));
        expect(theirs, orderedEquals(ours.$1));

        final encapsulated = _lines(
          _run(bin, ['kem-encap', level, _hexText(ours.$1)]),
        );
        expect(kem.decapsulate(ours.$2, encapsulated[0]), encapsulated[1]);

        final nonce = _fill(32, 0x22);
        final (ciphertext, shared) = kem.encapsulate(ours.$1, nonce);
        final opened = _hex(
          _run(bin, ['kem-decap', level, _hexText(seed), _hexText(ciphertext)]),
        );
        expect(opened, orderedEquals(shared));
      });
    }
  });

  group('ML-DSA', () {
    const sets = {
      '44': DilithiumParams.mlDsa44,
      '65': DilithiumParams.mlDsa65,
      '87': DilithiumParams.mlDsa87,
    };
    for (final entry in sets.entries) {
      test('ML-DSA-${entry.key} seed and cross-verify', () {
        final seed = _fill(32, 0x33);
        final ours = MlDsa.generateKeyPairSeeded(entry.value, seed);
        final theirs = _hex(
          _run(bin, ['dsa-public', entry.key, _hexText(seed)]),
        );
        expect(theirs, orderedEquals(ours.$1));

        final signed = _hex(
          _run(bin, [
            'dsa-sign',
            entry.key,
            _hexText(seed),
            _hexText(message),
            _hexText(context),
          ]),
        );
        expect(
          MlDsa.verify(ours.$1, message, signed, entry.value, ctx: context),
          isTrue,
        );

        final rnd = _fill(32, 0x44);
        final signature = MlDsa.sign(
          ours.$2,
          message,
          entry.value,
          ctx: context,
          rnd: rnd,
        );
        final verdict = _run(bin, [
          'dsa-verify',
          entry.key,
          _hexText(ours.$1),
          _hexText(signature),
          _hexText(message),
          _hexText(context),
        ]).trim();
        expect(verdict, 'ok');
      });
    }
  });

  group('SLH-DSA', () {
    const sets = {
      'sha2-128s': SlhDsaParams.sha2128s,
      'shake-256f': SlhDsaParams.shake256f,
    };
    for (final entry in sets.entries) {
      test('${entry.key} seed and cross-verify', () {
        final n = entry.value.n;
        final secretSeed = _fill(n, 0x51);
        final secretPrf = _fill(n, 0x52);
        final publicSeed = _fill(n, 0x53);
        final seed = Uint8List(n * 3)
          ..setRange(0, n, secretSeed)
          ..setRange(n, n * 2, secretPrf)
          ..setRange(n * 2, n * 3, publicSeed);
        final ours = SlhDsa.generateKeyPairSeeded(
          entry.value,
          secretSeed,
          secretPrf,
          publicSeed,
        );
        final theirs = _hex(
          _run(bin, ['slh-public', entry.key, _hexText(seed)]),
        );
        expect(theirs, orderedEquals(ours.$1), reason: 'public key');

        final signed = _hex(
          _run(bin, [
            'slh-sign',
            entry.key,
            _hexText(seed),
            _hexText(message),
            _hexText(context),
          ]),
        );
        expect(
          SlhDsa.verify(
            ours.$1,
            message,
            signed,
            entry.value,
            context: context,
          ),
          isTrue,
        );

        final signature = SlhDsa.sign(
          ours.$2,
          message,
          entry.value,
          context: context,
          additionalRandomness: _fill(n, 0x54),
          allowSlowSigning: true,
        );
        final verdict = _run(bin, [
          'slh-verify',
          entry.key,
          _hexText(ours.$1),
          _hexText(signature),
          _hexText(message),
          _hexText(context),
        ]).trim();
        expect(verdict, 'ok');
      });
    }
  });
}

Uint8List _fill(int length, int byte) =>
    Uint8List(length)..fillRange(0, length, byte);

String _run(String bin, List<String> args) {
  final result = Process.runSync(bin, args);
  if (result.exitCode != 0) {
    throw StateError('${result.stderr}');
  }
  return result.stdout as String;
}

Uint8List _hex(String text) {
  final clean = text.trim();
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

List<Uint8List> _lines(String text) =>
    text.trim().split('\n').map(_hex).toList();

String _hexText(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
