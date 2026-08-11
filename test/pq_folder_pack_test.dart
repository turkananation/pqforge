import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

/// Phase 8: the sequential folder packer collapses a tree into one stream
/// (bounded memory) and restores it exactly, rejecting path-traversal entries
/// from an untrusted archive.
void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('pqpack_test_'));
  tearDown(() => dir.deleteSync(recursive: true));

  test(
    'pack/unpack round-trips a nested tree including an empty file',
    () async {
      final src = Directory('${dir.path}/src')..createSync();
      Directory('${src.path}/sub').createSync(recursive: true);
      final tree = <String, List<int>>{
        'a.txt': utf8.encode('alpha'),
        'sub/b.bin': List<int>.generate(5000, (i) => i & 0xFF),
        'sub/empty.dat': <int>[],
      };
      tree.forEach(
        (rel, bytes) => File('${src.path}/$rel').writeAsBytesSync(bytes),
      );
      final entries = [
        for (final rel in tree.keys)
          PqPackEntry(relativePath: rel, sourcePath: '${src.path}/$rel'),
      ];

      final packFile = File('${dir.path}/x.pack');
      final sink = await packFile.open(mode: FileMode.write);
      final packed = await PqFolderPack.pack(sink: sink, entries: entries);
      await sink.close();
      expect(packed, tree.length);

      final outDir = '${dir.path}/out';
      final source = await packFile.open();
      final unpacked = await PqFolderPack.unpack(
        source: source,
        outputDirPath: outDir,
      );
      await source.close();
      expect(unpacked, tree.length);

      tree.forEach((rel, bytes) {
        expect(File('$outDir/$rel').readAsBytesSync(), bytes);
      });
    },
  );

  test('packStream → encryptStream → decryptStream → unpackFromStream '
      'round-trips with no plaintext spool', () async {
    final forge = PqForge(profile: PqForgeProfile.compact);
    final keys = forge.generateKeys(profile: PqForgeProfile.compact);
    final cipher = PqForgeStreamCipher();

    final src = Directory('${dir.path}/src')..createSync();
    Directory('${src.path}/nested').createSync(recursive: true);
    final tree = <String, List<int>>{
      'top.txt': utf8.encode('top-level'),
      'nested/data.bin': List<int>.generate(70000, (i) => (i * 7) & 0xFF),
      'nested/empty.dat': <int>[],
    };
    tree.forEach(
      (rel, bytes) => File('${src.path}/$rel').writeAsBytesSync(bytes),
    );
    final entries = [
      for (final rel in tree.keys)
        PqPackEntry(relativePath: rel, sourcePath: '${src.path}/$rel'),
    ];

    final archive = File('${dir.path}/tree.pqf');
    final stats = await cipher.encryptStream(
      recipientPublicKey: keys.kemKeyPair.publicKey,
      source: PqFolderPack.packStream(entries),
      output: archive,
      profile: PqForgeProfile.compact,
      frameSize: 4096, // force multiple frames across entry boundaries
      signerSecretKey: keys.signatureKeyPair.secretKey,
    );
    expect(stats.signed, isTrue);
    expect(stats.frameCount, greaterThan(1));

    final outDir = '${dir.path}/restored';
    final count = await PqFolderPack.unpackFromStream(
      cipher.decryptStream(
        recipientSecretKey: keys.kemKeyPair.secretKey,
        input: archive,
        signerPublicKey: keys.signatureKeyPair.publicKey,
      ),
      outputDirPath: outDir,
    );
    expect(count, tree.length);
    tree.forEach((rel, bytes) {
      expect(File('$outDir/$rel').readAsBytesSync(), bytes);
    });
  });

  test(
    'unpackFromStream removes created files when the archive is truncated',
    () async {
      final forge = PqForge(profile: PqForgeProfile.compact);
      final keys = forge.generateKeys(profile: PqForgeProfile.compact);
      final cipher = PqForgeStreamCipher();

      final src = Directory('${dir.path}/src2')..createSync();
      File(
        '${src.path}/a.bin',
      ).writeAsBytesSync(List<int>.generate(9000, (i) => i & 0xFF));
      File(
        '${src.path}/b.bin',
      ).writeAsBytesSync(List<int>.generate(9000, (i) => (i + 1) & 0xFF));

      final archive = File('${dir.path}/trunc.pqf');
      await cipher.encryptStream(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        source: PqFolderPack.packStream([
          PqPackEntry(relativePath: 'a.bin', sourcePath: '${src.path}/a.bin'),
          PqPackEntry(relativePath: 'b.bin', sourcePath: '${src.path}/b.bin'),
        ]),
        output: archive,
        profile: PqForgeProfile.compact,
        frameSize: 1024,
      );
      // Drop the tail: the first entry decrypts fine, then truncation hits.
      final bytes = archive.readAsBytesSync();
      archive.writeAsBytesSync(
        Uint8List.sublistView(bytes, 0, bytes.length - 3000),
      );

      final outDir = '${dir.path}/trunc_out';
      await expectLater(
        PqFolderPack.unpackFromStream(
          cipher.decryptStream(
            recipientSecretKey: keys.kemKeyPair.secretKey,
            input: archive,
          ),
          outputDirPath: outDir,
        ),
        throwsA(isA<PqForgeException>()),
      );
      // No partial tree: everything the failed unpack created was removed.
      expect(File('$outDir/a.bin').existsSync(), isFalse);
      expect(File('$outDir/b.bin').existsSync(), isFalse);
    },
  );

  test('unpack rejects a path-traversal entry', () async {
    final path = PqBytes.utf8Bytes('../escape');
    final malicious = PqBytes.concat([
      PqBytes.uint32(path.length),
      path,
      PqBytes.uint64(0),
    ]);
    final packFile = File('${dir.path}/evil.pack')..writeAsBytesSync(malicious);

    final source = await packFile.open();
    try {
      await expectLater(
        PqFolderPack.unpack(source: source, outputDirPath: '${dir.path}/out'),
        throwsA(isA<PqForgeException>()),
      );
    } finally {
      await source.close();
    }
    expect(File('${dir.path}/escape').existsSync(), isFalse);
  });
}
