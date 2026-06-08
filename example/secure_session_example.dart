import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge_cryptography.dart';

Future<void> main() async {
  // A 32-byte session key. In practice this comes from PqForgeCombiner over a
  // hybrid (classical + ML-KEM) key exchange.
  final sessionKey = Uint8List.fromList(
    List<int>.generate(32, (i) => (i * 7 + 1) & 0xFF),
  );
  final payload = Uint8List.fromList(
    utf8.encode('classified county budget memo'),
  );
  final header = Uint8List.fromList(
    utf8.encode('routing:county=kajiado;seq=7'),
  );

  for (final suite in PqForgeCipherSuite.values) {
    print('== ${suite.id} ==');

    // Seal with the pure-Dart (PointyCastle) backend...
    final sender = PqForgeSecureSession(
      secretKey: sessionKey,
      cipherSuite: suite,
      engineProvider: PqForgeEngineProvider.pureDart,
    );
    final packet = await sender.encrypt(payload, associatedData: header);
    print(
      '  wire packet: ${packet.length} bytes '
      '(${suite.nonceLength}-byte nonce + ${payload.length} ciphertext '
      '+ ${suite.tagLength} tag)',
    );

    // ...and open with the native (cryptography) backend: fully interoperable.
    final receiver = PqForgeSecureSession(
      secretKey: sessionKey,
      cipherSuite: suite,
      engineProvider: PqForgeEngineProvider.nativeCryptography,
    );
    final opened = await receiver.decrypt(packet, associatedData: header);
    print('  cross-backend decrypt: "${utf8.decode(opened)}"');

    // Any tampering (here, a flipped tag byte) is rejected distinctly.
    final tampered = Uint8List.fromList(packet)..[packet.length - 1] ^= 0xFF;
    try {
      await receiver.decrypt(tampered, associatedData: header);
    } on PqForgeAuthTagException catch (error) {
      print('  tamper rejected: $error');
    }
  }
}
