@Tags(['benchmark'])
/// Per-operation cost probe: the fixed lattice costs (keygen / encaps / decaps /
/// sign / verify) and the bulk AEAD throughput of both engines on this host.
///
/// These are the numbers capacity planning extrapolates from (e.g. "how long
/// does a 100 GB folder take?", "what does per-file KEM overhead cost across
/// 50 000 files?"). Opt-in because it takes ~30 s:
///
/// ```sh
/// PQFORGE_PROBE=1 dart test -t benchmark test/performance_probe_test.dart
/// ```
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

void main() {
  final enabled = Platform.environment['PQFORGE_PROBE'] == '1';

  group(
    'per-op performance probe',
    () {
      test('lattice per-op costs (fixed per file/envelope)', () {
        const forge = PqForge();
        final rows = <List<String>>[];

        for (final kemAlg in [
          PqKemAlgorithm.mlKem512,
          PqKemAlgorithm.mlKem1024,
        ]) {
          final keygenMs = _medianMs(
            5,
            () => forge.generateKemKeyPair(algorithm: kemAlg),
          );
          final keys = forge.generateKemKeyPair(algorithm: kemAlg);
          final encapsMs = _medianMs(
            15,
            () => forge.encapsulate(keys.publicKey, algorithm: kemAlg),
          );
          final encapsulated = forge.encapsulate(
            keys.publicKey,
            algorithm: kemAlg,
          );
          final decapsMs = _medianMs(
            15,
            () => forge.decapsulate(
              keys.secretKey,
              encapsulated.ciphertext,
              algorithm: kemAlg,
            ),
          );
          rows.add([
            kemAlg.id,
            _fmt(keygenMs),
            _fmt(encapsMs),
            _fmt(decapsMs),
            '-',
            '-',
          ]);
        }

        final digest = Uint8List(32);
        for (final sigAlg in [
          PqSignatureAlgorithm.mlDsa44,
          PqSignatureAlgorithm.mlDsa87,
        ]) {
          final keygenMs = _medianMs(
            5,
            () => forge.generateSignatureKeyPair(algorithm: sigAlg),
          );
          final keys = forge.generateSignatureKeyPair(algorithm: sigAlg);
          // preHash:true over a 32-byte digest — exactly the envelope/header
          // signing path. Sign is rejection-sampled, so median over more runs.
          final signMs = _medianMs(
            15,
            () => forge.sign(
              keys.secretKey,
              digest,
              algorithm: sigAlg,
              preHash: true,
            ),
          );
          final signature = forge.sign(
            keys.secretKey,
            digest,
            algorithm: sigAlg,
            preHash: true,
          );
          final verifyMs = _medianMs(
            15,
            () => forge.verify(
              keys.publicKey,
              digest,
              signature,
              algorithm: sigAlg,
              preHash: true,
            ),
          );
          rows.add([
            sigAlg.id,
            _fmt(keygenMs),
            '-',
            '-',
            _fmt(signMs),
            _fmt(verifyMs),
          ]);
        }

        stdout
          ..writeln('\n=== lattice per-op costs (ms, median) ===')
          ..writeln('algorithm    | keygen | encaps | decaps | sign  | verify')
          ..writeln('-------------|--------|--------|--------|-------|-------');
        for (final row in rows) {
          stdout.writeln(
            '${row[0].padRight(12)} | ${row[1].padLeft(6)} | '
            '${row[2].padLeft(6)} | ${row[3].padLeft(6)} | '
            '${row[4].padLeft(5)} | ${row[5].padLeft(6)}',
          );
        }
      });

      test(
        'AEAD bulk throughput per engine',
        () async {
          final key = Uint8List(32);
          final nonce = Uint8List(12)..[11] = 1;
          final aad = Uint8List(0);
          final plaintext = Uint8List(4 * 1024 * 1024); // 4 MiB
          for (var i = 0; i < plaintext.length; i += 64) {
            plaintext[i] = i & 0xFF;
          }

          stdout.writeln(
            '\n=== AES-256-GCM bulk throughput (4 MiB, this host) ===',
          );
          for (final provider in PqForgeEngineProvider.values) {
            final cipher = PqForgeStreamCipher.forProvider(provider);
            final sw = Stopwatch()..start();
            final sealed = await cipher.engine.seal(
              key: key,
              nonce: nonce,
              plaintext: plaintext,
              aad: aad,
            );
            sw.stop();
            final sealMiBs = 4 / (sw.elapsedMicroseconds / 1e6);
            sw
              ..reset()
              ..start();
            await cipher.engine.open(
              key: key,
              nonce: nonce,
              cipherTextWithTag: sealed,
              aad: aad,
            );
            sw.stop();
            final openMiBs = 4 / (sw.elapsedMicroseconds / 1e6);
            stdout.writeln(
              '${provider.name.padRight(20)} seal ${sealMiBs.toStringAsFixed(2)} '
              'MiB/s | open ${openMiBs.toStringAsFixed(2)} MiB/s',
            );
          }
        },
        timeout: const Timeout(Duration(minutes: 5)),
      );
    },
    skip: enabled ? false : 'Set PQFORGE_PROBE=1 to run the per-op probe.',
  );
}

double _medianMs(int n, void Function() op) {
  op(); // warm-up (JIT)
  final samples = <double>[];
  for (var i = 0; i < n; i++) {
    final sw = Stopwatch()..start();
    op();
    sw.stop();
    samples.add(sw.elapsedMicroseconds / 1000);
  }
  samples.sort();
  return samples[samples.length ~/ 2];
}

String _fmt(double ms) =>
    ms >= 100 ? ms.toStringAsFixed(0) : ms.toStringAsFixed(2);
