import 'package:test/test.dart';

import '../tool/interop/hpke_flight.dart';

void main() {
  test('BoringSSL EVP_HPKE base and auth', () async {
    final ran = await runBoringSslHpkeFlight();
    if (!ran) {
      markTestSkipped('pinned BoringSSL build is not present');
    }
  }, timeout: const Timeout(Duration(minutes: 2)));
}
