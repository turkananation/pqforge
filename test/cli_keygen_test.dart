import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

import '../bin/pqforge.dart';
import '../bin/src/console.dart';
import '../bin/src/support.dart';

void main() {
  setUpAll(() => Console.configure(color: false));

  late Directory outDir;

  setUp(() async {
    outDir = await Directory.systemTemp.createTemp('pqforge-cli-keygen-');
  });

  tearDown(() async {
    if (await outDir.exists()) await outDir.delete(recursive: true);
  });

  Future<void> runCli(List<String> args) => PqForgeRunner().run(args);

  test('default keygen emits ML-KEM, ML-DSA, SLH-DSA, and classical', () async {
    await runCli([
      'keygen',
      '--profile',
      'maximum',
      '--key-id',
      'vault',
      '--out-dir',
      outDir.path,
    ]);

    for (final name in [
      'vault.kem.public.json',
      'vault.sign.public.json',
      'vault.slh-dsa-shake-256f.public.json',
      'vault.x25519.public.json',
      'vault.ed25519.public.json',
      'vault.ecdsa-p256.public.json',
      'vault.kem.secret.json',
      'vault.sign.secret.json',
      'vault.slh-dsa-shake-256f.secret.json',
    ]) {
      expect(File('${outDir.path}/$name').existsSync(), isTrue, reason: name);
    }

    final slhPublic = PqExportedKey.fromJson(
      Map<String, Object?>.from(
        jsonDecode(
              await File(
                '${outDir.path}/vault.slh-dsa-shake-256f.public.json',
              ).readAsString(),
            )
            as Map,
      ),
    );
    expect(slhPublic.kind, PqKeyKind.signaturePublic);
    expect(slhPublic.algorithmId, PqSlhDsaAlgorithm.shake256f.id);
    expect(
      slhPublic.bytes,
      hasLength(PqSlhDsaAlgorithm.shake256f.publicKeyBytes),
    );
  });

  test(
    'keygen --slh-dsa-only emits the profile-matched SHAKE-f keypair',
    () async {
      await runCli([
        'keygen',
        '--profile',
        'compact',
        '--key-id',
        'archive',
        '--out-dir',
        outDir.path,
        '--slh-dsa-only',
      ]);

      final publicFile = File(
        '${outDir.path}/archive.slh-dsa-shake-128f.public.json',
      );
      final secretFile = File(
        '${outDir.path}/archive.slh-dsa-shake-128f.secret.json',
      );
      expect(await publicFile.exists(), isTrue);
      expect(await secretFile.exists(), isTrue);
      expect(
        File('${outDir.path}/archive.kem.public.json').existsSync(),
        isFalse,
      );
      expect(
        File('${outDir.path}/archive.x25519.public.json').existsSync(),
        isFalse,
      );

      final publicKey = PqExportedKey.fromJson(
        Map<String, Object?>.from(
          jsonDecode(await publicFile.readAsString()) as Map,
        ),
      );
      final secretKey = PqExportedKey.fromJson(
        Map<String, Object?>.from(
          jsonDecode(await secretFile.readAsString()) as Map,
        ),
      );
      expect(publicKey.kind, PqKeyKind.signaturePublic);
      expect(secretKey.kind, PqKeyKind.signatureSecret);
      expect(publicKey.algorithmId, PqSlhDsaAlgorithm.shake128f.id);
      expect(secretKey.algorithmId, PqSlhDsaAlgorithm.shake128f.id);
      expect(
        publicKey.bytes,
        hasLength(PqSlhDsaAlgorithm.shake128f.publicKeyBytes),
      );
      expect(
        secretKey.bytes,
        hasLength(PqSlhDsaAlgorithm.shake128f.secretKeyBytes),
      );
    },
  );

  test('keygen --no-classical includes ML-KEM, ML-DSA, and SLH-DSA', () async {
    await runCli([
      'keygen',
      '--profile',
      'compact',
      '--key-id',
      'vault',
      '--out-dir',
      outDir.path,
      '--no-classical',
    ]);

    expect(File('${outDir.path}/vault.kem.public.json').existsSync(), isTrue);
    expect(File('${outDir.path}/vault.sign.public.json').existsSync(), isTrue);
    expect(
      File('${outDir.path}/vault.slh-dsa-shake-128f.public.json').existsSync(),
      isTrue,
    );
    expect(
      File('${outDir.path}/vault.ed25519.public.json').existsSync(),
      isFalse,
    );
  });

  test('keygen --no-slh-dsa skips hash-based keys', () async {
    await runCli([
      'keygen',
      '--profile',
      'compact',
      '--key-id',
      'vault',
      '--out-dir',
      outDir.path,
      '--no-classical',
      '--no-slh-dsa',
    ]);

    expect(File('${outDir.path}/vault.kem.public.json').existsSync(), isTrue);
    expect(File('${outDir.path}/vault.sign.public.json').existsSync(), isTrue);
    expect(
      File('${outDir.path}/vault.slh-dsa-shake-128f.public.json').existsSync(),
      isFalse,
    );
  });

  test('keygen --slh-dsa emits the requested sets', () async {
    await runCli([
      'keygen',
      '--profile',
      'compact',
      '--key-id',
      'multi',
      '--out-dir',
      outDir.path,
      '--slh-dsa-only',
      '--slh-dsa',
      'slh-dsa-sha2-128f',
      '--slh-dsa',
      'slh-dsa-shake-128f',
    ]);

    expect(
      File('${outDir.path}/multi.slh-dsa-sha2-128f.public.json').existsSync(),
      isTrue,
    );
    expect(
      File('${outDir.path}/multi.slh-dsa-shake-128f.public.json').existsSync(),
      isTrue,
    );
    expect(
      File('${outDir.path}/multi.slh-dsa-shake-192f.public.json').existsSync(),
      isFalse,
    );
  });

  test('keygen --classical-only skips SLH-DSA', () async {
    await runCli([
      'keygen',
      '--profile',
      'compact',
      '--key-id',
      'classic',
      '--out-dir',
      outDir.path,
      '--classical-only',
    ]);

    expect(
      File('${outDir.path}/classic.x25519.public.json').existsSync(),
      isTrue,
    );
    expect(
      File(
        '${outDir.path}/classic.slh-dsa-shake-128f.public.json',
      ).existsSync(),
      isFalse,
    );
    expect(
      File('${outDir.path}/classic.kem.public.json').existsSync(),
      isFalse,
    );
  });

  test('keygen wraps SLH-DSA secrets with the same Argon2id path', () async {
    await runCli([
      'keygen',
      '--profile',
      'compact',
      '--key-id',
      'archive',
      '--out-dir',
      outDir.path,
      '--slh-dsa-only',
      '--passphrase',
      'test-passphrase',
      '--argon-iterations',
      '1',
      '--argon-memory-power-of-2',
      '10',
      '--argon-lanes',
      '1',
    ]);

    final wrappedPath =
        '${outDir.path}/archive.slh-dsa-shake-128f.secret.wrapped.json';
    expect(File(wrappedPath).existsSync(), isTrue);
    expect(
      File(
        '${outDir.path}/archive.slh-dsa-shake-128f.secret.json',
      ).existsSync(),
      isFalse,
    );

    final wrapped = PqWrappedKey.fromJson(
      Map<String, Object?>.from(
        jsonDecode(await File(wrappedPath).readAsString()) as Map,
      ),
    );
    expect(wrapped.algorithmId, PqSlhDsaAlgorithm.shake128f.id);
    expect(wrapped.keyKind, PqKeyKind.signatureSecret);
    final opened = const PqForge().unwrapKeyWithPassphrase(
      wrapped,
      'test-passphrase',
    );
    expect(opened.kind, PqKeyKind.signatureSecret);
    expect(opened.bytes, hasLength(PqSlhDsaAlgorithm.shake128f.secretKeyBytes));
  });

  test(
    'sign and verify round-trip an SLH-DSA document key from keygen',
    () async {
      await runCli([
        'keygen',
        '--profile',
        'compact',
        '--key-id',
        'signer',
        '--out-dir',
        outDir.path,
        '--slh-dsa-only',
      ]);

      final document = File('${outDir.path}/contract.txt');
      await document.writeAsString('signed with SLH-DSA-SHAKE-128f\n');
      final signaturePath = '${outDir.path}/contract.sig.json';

      await runCli([
        'sign',
        '--signer-secret',
        '${outDir.path}/signer.slh-dsa-shake-128f.secret.json',
        '--kind',
        'document',
        '--in',
        document.path,
        '--document-id',
        'contract-1',
        '--out',
        signaturePath,
      ]);

      final sigJson =
          jsonDecode(await File(signaturePath).readAsString()) as Map;
      expect(sigJson['signatureAlgorithm'], PqSlhDsaAlgorithm.shake128f.id);
      expect(sigJson['kind'], 'document');

      await runCli([
        'verify',
        '--signer-public',
        '${outDir.path}/signer.slh-dsa-shake-128f.public.json',
        '--in',
        document.path,
        '--signature',
        signaturePath,
      ]);
    },
  );

  test('sign and verify round-trip an SLH-DSA artifact from keygen', () async {
    await runCli([
      'keygen',
      '--profile',
      'compact',
      '--key-id',
      'release',
      '--out-dir',
      outDir.path,
      '--slh-dsa-only',
    ]);

    final artifact = File('${outDir.path}/firmware.bin');
    await artifact.writeAsBytes(Uint8List.fromList([1, 2, 3, 4, 5]));
    final signaturePath = '${outDir.path}/firmware.sig.json';

    await runCli([
      'sign',
      '--signer-secret',
      '${outDir.path}/release.slh-dsa-shake-128f.secret.json',
      '--kind',
      'artifact',
      '--in',
      artifact.path,
      '--artifact-id',
      'firmware',
      '--version',
      '9',
      '--out',
      signaturePath,
    ]);

    final sigJson = jsonDecode(await File(signaturePath).readAsString()) as Map;
    expect(sigJson['signatureAlgorithm'], PqSlhDsaAlgorithm.shake128f.id);
    expect(sigJson['kind'], 'artifact');
    expect(sigJson['artifactId'], 'firmware');
    expect(sigJson['version'], 9);

    await runCli([
      'verify',
      '--signer-public',
      '${outDir.path}/release.slh-dsa-shake-128f.public.json',
      '--in',
      artifact.path,
      '--signature',
      signaturePath,
    ]);
  });

  test('envelope signer-secret rejects an SLH-DSA key', () {
    final key = PqExportedKey(
      kind: PqKeyKind.signatureSecret,
      algorithmId: PqSlhDsaAlgorithm.shake128f.id,
      bytes: Uint8List(PqSlhDsaAlgorithm.shake128f.secretKeyBytes),
    );
    expect(
      () => requireMlDsaSignatureKey(key),
      throwsA(
        isA<PqForgeException>().having(
          (error) => error.message,
          'message',
          contains('SLH-DSA keys cannot sign envelopes'),
        ),
      ),
    );
  });

  test('flag conflicts are rejected', () async {
    expect(
      () => runCli([
        'keygen',
        '--out-dir',
        outDir.path,
        '--no-slh-dsa',
        '--slh-dsa-only',
      ]),
      throwsA(isA<PqForgeException>()),
    );
    expect(
      () => runCli([
        'keygen',
        '--out-dir',
        outDir.path,
        '--slh-dsa-only',
        '--classical-only',
      ]),
      throwsA(isA<PqForgeException>()),
    );
  });
}
