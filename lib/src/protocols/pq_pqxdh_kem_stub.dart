/// ML-KEM for PQXDH on this isolate. dart2wasm has no `dart:isolate`.
library;

import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_lattice_provider.dart';

/// Encapsulates to an ML-KEM-1024 public key. [coins] is the 32-byte `m`.
Future<(Uint8List, Uint8List)> pqxdhKemEncapsulate(
  Uint8List publicKey,
  Uint8List coins,
) async {
  return PqLattice.provider.kemEncapsulate(
    PqKemAlgorithm.mlKem1024,
    publicKey,
    nonce: coins,
  );
}

/// Decapsulates an ML-KEM-1024 ciphertext.
Future<Uint8List> pqxdhKemDecapsulate(
  Uint8List secretKey,
  Uint8List ciphertext,
) async {
  return PqLattice.provider.kemDecapsulate(
    PqKemAlgorithm.mlKem1024,
    secretKey,
    ciphertext,
  );
}
