/// ML-KEM for PQXDH. The pure-Dart backend runs on a worker isolate so a
/// Flutter caller stays responsive. A registered [PqLattice] backend stays
/// on the caller: a new isolate would not see it.
library;

import 'dart:isolate';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_lattice_provider.dart';

/// Encapsulates to an ML-KEM-1024 public key. [coins] is the 32-byte `m`.
Future<(Uint8List, Uint8List)> pqxdhKemEncapsulate(
  Uint8List publicKey,
  Uint8List coins,
) {
  if (PqLattice.provider is! PqPureDartLatticeProvider) {
    return Future.value(_encapsulate(publicKey, coins));
  }
  return Isolate.run(() => _encapsulate(publicKey, coins));
}

/// Decapsulates an ML-KEM-1024 ciphertext.
Future<Uint8List> pqxdhKemDecapsulate(
  Uint8List secretKey,
  Uint8List ciphertext,
) {
  if (PqLattice.provider is! PqPureDartLatticeProvider) {
    return Future.value(_decapsulate(secretKey, ciphertext));
  }
  return Isolate.run(() => _decapsulate(secretKey, ciphertext));
}

(Uint8List, Uint8List) _encapsulate(Uint8List publicKey, Uint8List coins) {
  return PqLattice.provider.kemEncapsulate(
    PqKemAlgorithm.mlKem1024,
    publicKey,
    nonce: coins,
  );
}

Uint8List _decapsulate(Uint8List secretKey, Uint8List ciphertext) {
  return PqLattice.provider.kemDecapsulate(
    PqKemAlgorithm.mlKem1024,
    secretKey,
    ciphertext,
  );
}
