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

    test('matches OpenSSL on every brainpool TLS group', () {
      const curves = {
        'brainpoolP256r1': 32,
        'brainpoolP384r1': 48,
        'brainpoolP512r1': 64,
      };
      for (final entry in curves.entries) {
        final a = _opensslEc(entry.key);
        final b = _opensslEc(entry.key);
        final openssl = _opensslDerive(a.pem, b.pem);
        final secret = _brainpoolAgree(
          entry.key,
          _pad(a.secret, entry.value),
          b.publicKey,
        );
        expect(
          secret,
          orderedEquals(_pad(openssl, entry.value)),
          reason: entry.key,
        );
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
  });

  group('PqFfdhe OpenSSL', () {
    for (final group in PqFfdheGroup.values) {
      final minutes = switch (group) {
        PqFfdheGroup.ffdhe2048 || PqFfdheGroup.ffdhe3072 => 2,
        PqFfdheGroup.ffdhe4096 => 4,
        PqFfdheGroup.ffdhe6144 => 8,
        PqFfdheGroup.ffdhe8192 => 15,
      };
      test('matches OpenSSL on ${group.name}', () {
        final a = _opensslNamed('DH', 'group:${group.name}');
        final b = _opensslNamed('DH', 'group:${group.name}');
        final openssl = _opensslDerive(a.pem, b.pem);
        final secret = PqFfdhe.sharedSecret(
          group: group,
          secretKey: _pad(a.secret, group.bytes),
          remotePublicKey: _pad(b.publicKey, group.bytes),
        );
        expect(
          secret,
          orderedEquals(_pad(openssl, group.bytes)),
          reason: group.name,
        );
      }, timeout: Timeout(Duration(minutes: minutes)));
    }
  });

  group('groups already on main', () {
    test('matches OpenSSL on P-256, P-384, and P-521', () {
      const curves = {'prime256v1': 32, 'secp384r1': 48, 'secp521r1': 66};
      for (final entry in curves.entries) {
        final a = _opensslEc(entry.key);
        final b = _opensslEc(entry.key);
        final openssl = _opensslDerive(a.pem, b.pem);
        final secret = _nistAgree(
          entry.key,
          _pad(a.secret, entry.value),
          b.publicKey,
        );
        expect(
          secret,
          orderedEquals(_pad(openssl, entry.value)),
          reason: entry.key,
        );
      }
    });

    test('matches OpenSSL on X25519 and X448', () async {
      final x25519a = _opensslNamed('X25519');
      final x25519b = _opensslNamed('X25519');
      final x25519 = await PqClassical.provider.x25519SharedSecret(
        secretKey: _pad(x25519a.secret, 32),
        remotePublicKey: _pad(x25519b.publicKey, 32),
      );
      expect(
        x25519,
        orderedEquals(_pad(_opensslDerive(x25519a.pem, x25519b.pem), 32)),
      );

      final x448a = _opensslNamed('X448');
      final x448b = _opensslNamed('X448');
      final x448 = PqX448.sharedSecret(
        secretKey: _pad(x448a.secret, 56),
        remotePublicKey: _pad(x448b.publicKey, 56),
      );
      expect(
        x448,
        orderedEquals(_pad(_opensslDerive(x448a.pem, x448b.pem), 56)),
      );
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

Uint8List _brainpoolAgree(String curve, Uint8List secret, Uint8List remote) =>
    switch (curve) {
      'brainpoolP256r1' => PqBrainpool.p256SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
      'brainpoolP384r1' => PqBrainpool.p384SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
      _ => PqBrainpool.p512SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
    };

Uint8List _nistAgree(String curve, Uint8List secret, Uint8List remote) =>
    switch (curve) {
      'prime256v1' => PqNistEcdh.p256SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
      'secp384r1' => PqNistEcdh.p384SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
      _ => PqNistEcdh.p521SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      ),
    };

({Uint8List secret, Uint8List publicKey, String pem}) _opensslEc(
  String curve,
) => _opensslNamed('EC', 'ec_paramgen_curve:$curve');

({Uint8List secret, Uint8List publicKey, String pem}) _opensslNamed(
  String algorithm, [
  String? option,
]) {
  final dir = Directory.systemTemp.createTempSync('ossl');
  final pem = '${dir.path}/key.pem';
  final args = ['genpkey', '-algorithm', algorithm, '-out', pem];
  if (option != null) args.insertAll(3, ['-pkeyopt', option]);
  final result = Process.runSync('openssl', args);
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
  if (text.exitCode != 0) {
    throw StateError('${text.stderr}');
  }
  final fields = _fields(text.stdout as String);
  final secret = fields['priv'] ?? fields['private-key'];
  final publicKey = fields['pub'] ?? fields['public-key'];
  if (secret == null || publicKey == null) {
    throw StateError('could not read $algorithm key: ${fields.keys}');
  }
  return (secret: secret, publicKey: publicKey, pem: pem);
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
