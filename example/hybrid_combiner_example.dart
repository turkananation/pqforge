import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
// The core combiner (Option A) is part of package:pqforge/pqforge.dart; the
// SecretKey extension (Option B) lives behind the cryptography entrypoint.
import 'package:pqforge/pqforge.dart';

Future<void> main() async {
  // In a real handshake these come from two independent key exchanges:
  //   classical   = X25519 / ECDHE shared secret (length fixed by the curve)
  //   postQuantum = ML-KEM decapsulated shared secret (32 bytes)
  final forge = PqForge();
  final recipient = forge.generateKemKeyPair();
  final kem = forge.encapsulate(recipient.publicKey);
  final postQuantum = kem.sharedSecret;
  final classical = PqBytes.randomBytes(32); // stand-in for X25519 output

  // Domain separation: pin the protocol, version, and role into `info`.
  final info = PqBytes.utf8Bytes('pqforge/demo-session/v1/client->server');
  final salt = PqBytes.sha256(PqBytes.utf8Bytes('demo-transcript'));

  print('== Option A: core PqForgeCombiner (raw bytes) ==');
  const combiner = PqForgeCombiner.balanced(); // SHA-256 / ML-KEM-768 class
  final coreKey = combiner.combine(
    classicalSharedSecret: classical,
    postQuantumSharedSecret: postQuantum,
    info: info,
    salt: salt,
  );
  print('core session key: ${coreKey.length} bytes');

  print('\n== Option B: SecretKey extension (package:cryptography) ==');
  final session = await SecretKey(classical).deriveHybridSecretKey(
    postQuantumSecret: SecretKey(postQuantum),
    info: info,
    salt: salt,
  );
  final extKey = Uint8List.fromList(await session.extractBytes());
  print('extension session key: ${extKey.length} bytes');

  print(
    '\nboth entry strategies agree: '
    '${PqBytes.constantTimeEquals(coreKey, extKey)}',
  );

  print('\n== Heavy profile (SHA-512 / ML-KEM-1024 class) ==');
  final heavyKey = const PqForgeCombiner.heavy().combine(
    classicalSharedSecret: classical,
    postQuantumSharedSecret: postQuantum,
    info: info,
    salt: salt,
  );
  print('heavy session key: ${heavyKey.length} bytes');
}
