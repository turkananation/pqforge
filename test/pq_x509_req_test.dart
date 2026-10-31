import 'dart:io';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  test('openssl -subj and -addext mint a request OpenSSL verifies', () {
    final openssl = Process.runSync('openssl', ['version']);
    if (openssl.exitCode != 0) {
      markTestSkipped('openssl is not on PATH');
    }
    final dir = Directory.systemTemp.createTempSync('pqforge-req-');
    try {
      _openssl([
        'ecparam',
        '-name',
        'prime256v1',
        '-genkey',
        '-noout',
        '-out',
        '${dir.path}/leaf.key',
      ]);
      _openssl([
        'ecparam',
        '-name',
        'prime256v1',
        '-genkey',
        '-noout',
        '-out',
        '${dir.path}/ca.key',
      ]);
      _openssl([
        'req',
        '-new',
        '-key',
        '${dir.path}/leaf.key',
        '-out',
        '${dir.path}/openssl.csr',
        '-subj',
        '/C=KE/ST=Nairobi/O=pqforge/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost',
      ]);
      final ours = Process.runSync(Platform.resolvedExecutable, [
        'run',
        'pqforge',
        'cert',
        'req',
        '--key',
        '${dir.path}/leaf.key',
        '--subj',
        '/C=KE/ST=Nairobi/O=pqforge/CN=localhost',
        '--addext',
        'subjectAltName=DNS:localhost',
        '--out',
        '${dir.path}/ours.csr',
      ], workingDirectory: Directory.current.path);
      expect(ours.exitCode, 0, reason: '${ours.stdout}${ours.stderr}');
      final verified = _openssl([
        'req',
        '-in',
        '${dir.path}/ours.csr',
        '-noout',
        '-verify',
        '-subject',
      ]);
      expect(verified, contains('verify OK'));
      expect(verified, contains('C = KE'));
      expect(verified, contains('CN = localhost'));

      final issued = Process.runSync(Platform.resolvedExecutable, [
        'run',
        'pqforge',
        'cert',
        'issue',
        '--key',
        '${dir.path}/ca.key',
        '--subj',
        '/CN=pqforge-ca',
        '--ca',
        '--days',
        '30',
        '--out',
        '${dir.path}/ca.pem',
      ]);
      expect(issued.exitCode, 0, reason: '${issued.stderr}');
      final signed = Process.runSync(Platform.resolvedExecutable, [
        'run',
        'pqforge',
        'cert',
        'sign',
        '--in',
        '${dir.path}/openssl.csr',
        '--ca',
        '${dir.path}/ca.pem',
        '--ca-key',
        '${dir.path}/ca.key',
        '--days',
        '30',
        '--out',
        '${dir.path}/leaf.pem',
      ]);
      expect(signed.exitCode, 0, reason: '${signed.stdout}${signed.stderr}');
      expect(
        _openssl([
          'verify',
          '-CAfile',
          '${dir.path}/ca.pem',
          '${dir.path}/leaf.pem',
        ]),
        contains('OK'),
      );
      _openssl([
        'x509',
        '-req',
        '-in',
        '${dir.path}/ours.csr',
        '-CA',
        '${dir.path}/ca.pem',
        '-CAkey',
        '${dir.path}/ca.key',
        '-CAcreateserial',
        '-copy_extensions',
        'copy',
        '-out',
        '${dir.path}/from-openssl.pem',
        '-days',
        '30',
      ]);
      final checked = Process.runSync(Platform.resolvedExecutable, [
        'run',
        'pqforge',
        'cert',
        'verify',
        '--in',
        '${dir.path}/from-openssl.pem',
        '--anchor',
        '${dir.path}/ca.pem',
      ]);
      expect(checked.exitCode, 0, reason: '${checked.stdout}${checked.stderr}');
      expect(checked.stdout, contains('OK'));
    } finally {
      dir.deleteSync(recursive: true);
    }
  });
}

String _openssl(List<String> args) {
  final result = Process.runSync('openssl', args);
  expect(result.exitCode, 0, reason: '${result.stdout}${result.stderr}');
  return '${result.stdout}${result.stderr}';
}
