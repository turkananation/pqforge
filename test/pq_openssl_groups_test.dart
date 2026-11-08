import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqBrainpool', () {
    for (final curve in const ['p256', 'p384', 'p512']) {
      test('$curve parties agree', () {
        final a = _generate(curve);
        final b = _generate(curve);
        final ab = _agree(curve, a.secretKey, b.publicKey);
        final ba = _agree(curve, b.secretKey, a.publicKey);
        expect(ab, orderedEquals(ba));
        expect(ab.length, _secretBytes(curve));
        expect(a.publicKey.first, 0x04);
      });
    }

    test('rejects a truncated point and a scalar of zero', () {
      expect(
        () => PqBrainpool.p256SharedSecret(
          secretKey: Uint8List(32),
          remotePublicKey: Uint8List(65),
        ),
        throwsArgumentError,
      );
      final pair = PqBrainpool.p256GenerateKeyPair();
      expect(
        () => PqBrainpool.p256SharedSecret(
          secretKey: Uint8List(32),
          remotePublicKey: pair.publicKey,
        ),
        throwsArgumentError,
      );
    });

    test('matches OpenSSL on brainpoolP256r1 and brainpoolP512r1', () {
      for (final curve in const ['brainpoolP256r1', 'brainpoolP512r1']) {
        final ours = curve.endsWith('256r1') ? 'p256' : 'p512';
        final width = ours == 'p256' ? 32 : 64;
        final a = _opensslKey(curve);
        final b = _opensslKey(curve);
        final openssl = _opensslDerive(a.pem, b.pem);
        final secret = _agree(ours, _pad(a.secret, width), b.publicKey);
        expect(secret, orderedEquals(_pad(openssl, width)));
      }
    });
  });

  group('PqFfdhe', () {
    test('two parties agree on ffdhe2048', () {
      final a = PqFfdhe.generateKeyPair(PqFfdheGroup.ffdhe2048);
      final b = PqFfdhe.generateKeyPair(PqFfdheGroup.ffdhe2048);
      final ab = PqFfdhe.sharedSecret(
        group: PqFfdheGroup.ffdhe2048,
        secretKey: a.secretKey,
        remotePublicKey: b.publicKey,
      );
      final ba = PqFfdhe.sharedSecret(
        group: PqFfdheGroup.ffdhe2048,
        secretKey: b.secretKey,
        remotePublicKey: a.publicKey,
      );
      expect(ab, orderedEquals(ba));
      expect(ab, hasLength(256));
    });

    test('rejects 1 and a value outside the subgroup', () {
      final one = Uint8List(256)..[255] = 1;
      final pair = PqFfdhe.generateKeyPair(PqFfdheGroup.ffdhe2048);
      expect(
        () => PqFfdhe.sharedSecret(
          group: PqFfdheGroup.ffdhe2048,
          secretKey: pair.secretKey,
          remotePublicKey: one,
        ),
        throwsArgumentError,
      );
    });

    test('matches OpenSSL on ffdhe2048 and ffdhe3072', () {
      for (final name in const ['ffdhe2048', 'ffdhe3072']) {
        final group = name == 'ffdhe2048'
            ? PqFfdheGroup.ffdhe2048
            : PqFfdheGroup.ffdhe3072;
        final a = _opensslDh(name);
        final b = _opensslDh(name);
        final openssl = _opensslDerive(a.pem, b.pem);
        final secret = PqFfdhe.sharedSecret(
          group: group,
          secretKey: _pad(a.secret, group.bytes),
          remotePublicKey: _pad(b.publicKey, group.bytes),
        );
        expect(secret, orderedEquals(_pad(openssl, group.bytes)));
      }
    });
  });
}

({Uint8List publicKey, Uint8List secretKey}) _generate(String curve) =>
    switch (curve) {
      'p256' => PqBrainpool.p256GenerateKeyPair(),
      'p384' => PqBrainpool.p384GenerateKeyPair(),
      _ => PqBrainpool.p512GenerateKeyPair(),
    };

Uint8List _agree(String curve, Uint8List secret, Uint8List remote) =>
    switch (curve) {
      'p256' => PqBrainpool.p256SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
      'p384' => PqBrainpool.p384SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
      _ => PqBrainpool.p512SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
    };

int _secretBytes(String curve) => switch (curve) {
  'p256' => 32,
  'p384' => 48,
  _ => 64,
};

({Uint8List secret, Uint8List publicKey, String pem}) _opensslKey(
  String curve,
) {
  final dir = Directory.systemTemp.createTempSync('bp');
  final pem = '${dir.path}/key.pem';
  final result = Process.runSync('openssl', [
    'genpkey',
    '-algorithm',
    'EC',
    '-pkeyopt',
    'ec_paramgen_curve:$curve',
    '-out',
    pem,
  ]);
  if (result.exitCode != 0) {
    throw StateError('${result.stderr}');
  }
  final text = Process.runSync('openssl', [
    'pkey',
    '-in',
    pem,
    '-text',
    '-noout',
  ]);
  final fields = _fields(text.stdout as String);
  return (secret: fields['priv']!, publicKey: fields['pub']!, pem: pem);
}

({Uint8List secret, Uint8List publicKey, String pem}) _opensslDh(String group) {
  final dir = Directory.systemTemp.createTempSync('dh');
  final pem = '${dir.path}/key.pem';
  final result = Process.runSync('openssl', [
    'genpkey',
    '-algorithm',
    'DH',
    '-pkeyopt',
    'group:$group',
    '-out',
    pem,
  ]);
  if (result.exitCode != 0) {
    throw StateError('${result.stderr}');
  }
  final text = Process.runSync('openssl', [
    'pkey',
    '-in',
    pem,
    '-text',
    '-noout',
  ]);
  final fields = _fields(text.stdout as String);
  return (
    secret: fields['private-key']!,
    publicKey: fields['public-key']!,
    pem: pem,
  );
}

Uint8List _opensslDerive(String ours, String peer) {
  final pub = '$peer.pub';
  final exported = Process.runSync('openssl', [
    'pkey',
    '-in',
    peer,
    '-pubout',
    '-out',
    pub,
  ]);
  if (exported.exitCode != 0) {
    throw StateError('${exported.stderr}');
  }
  final out = '$ours.secret';
  final result = Process.runSync('openssl', [
    'pkeyutl',
    '-derive',
    '-inkey',
    ours,
    '-peerkey',
    pub,
    '-out',
    out,
  ]);
  if (result.exitCode != 0) {
    throw StateError('${result.stderr}');
  }
  return Uint8List.fromList(File(out).readAsBytesSync());
}

Map<String, Uint8List> _fields(String text) {
  final out = <String, Uint8List>{};
  String? name;
  final hex = StringBuffer();
  for (final raw in text.split('\n')) {
    final line = raw.trim();
    if (line.endsWith(':') && RegExp(r'[g-z]').hasMatch(line)) {
      if (name != null) out[name] = _hex(hex.toString());
      name = line.substring(0, line.length - 1);
      hex.clear();
      continue;
    }
    if (RegExp(r'^[0-9a-f:]+$').hasMatch(line)) {
      hex.write(line.replaceAll(':', ''));
    }
  }
  if (name != null && hex.isNotEmpty) out[name] = _hex(hex.toString());
  return out;
}

Uint8List _hex(String text) {
  final out = Uint8List(text.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(text.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Uint8List _pad(Uint8List bytes, int length) {
  if (bytes.length == length) return bytes;
  if (bytes.length == length + 1 && bytes.first == 0) {
    return Uint8List.sublistView(bytes, 1);
  }
  if (bytes.length > length) {
    throw StateError('value is longer than the group');
  }
  final out = Uint8List(length);
  out.setRange(length - bytes.length, length, bytes);
  return out;
}
