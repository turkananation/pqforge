import 'package:test/test.dart';

import '../tool/interop/openssl_hpke_flight.dart';

void main() {
  test('OpenSSL HPKE X448 and P-521', () async {
    final ran = await runOpenSslHpkeFlight();
    if (!ran) {
      markTestSkipped('pinned OpenSSL build is not present');
    }
  }, timeout: const Timeout(Duration(minutes: 3)));
}
