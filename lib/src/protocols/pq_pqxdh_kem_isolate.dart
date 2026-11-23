/// ML-KEM and bundle-trust signatures for PQXDH. The pure-Dart backend runs
/// on a worker isolate so a Flutter caller stays responsive. A registered
/// [PqLattice] backend stays on the caller: a new isolate would not see it.
/// SLH-DSA does not use that backend, so it still offloads.
library;

import 'dart:isolate';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_lattice_provider.dart';
import '../primitives/pq_primitives.dart';

/// Encapsulates to [algorithm]. [coins] is the 32-byte `m`.
/// [offload] is ignored when a custom lattice provider is installed, and
/// when the caller is already on a worker.
Future<(Uint8List, Uint8List)> pqxdhKemEncapsulate(
  Uint8List publicKey,
  Uint8List coins, {
  PqKemAlgorithm algorithm = PqKemAlgorithm.mlKem1024,
  bool offload = true,
}) {
  if (!offload || PqLattice.provider is! PqPureDartLatticeProvider) {
    return Future.value(_encapsulate(algorithm, publicKey, coins));
  }
  return Isolate.run(() => _encapsulate(algorithm, publicKey, coins));
}

/// Decapsulates [algorithm].
Future<Uint8List> pqxdhKemDecapsulate(
  Uint8List secretKey,
  Uint8List ciphertext, {
  PqKemAlgorithm algorithm = PqKemAlgorithm.mlKem1024,
  bool offload = true,
}) {
  if (!offload || PqLattice.provider is! PqPureDartLatticeProvider) {
    return Future.value(_decapsulate(algorithm, secretKey, ciphertext));
  }
  return Isolate.run(() => _decapsulate(algorithm, secretKey, ciphertext));
}

/// Signs the bundle trust message. An `s` set is allowed: the caller named it.
/// ML-DSA stays on the caller when a custom lattice provider is installed.
Future<Uint8List> pqxdhTrustSign(
  Uint8List secretKey,
  Uint8List message, {
  PqSignatureAlgorithm? mlDsa,
  PqSlhDsaAlgorithm? slhDsa,
  bool offload = true,
}) {
  if (!_offloadTrust(offload, slhDsa)) {
    return Future.value(_trustSign(secretKey, message, mlDsa, slhDsa));
  }
  return Isolate.run(() => _trustSign(secretKey, message, mlDsa, slhDsa));
}

/// Verifies the bundle trust message.
Future<bool> pqxdhTrustVerify(
  Uint8List publicKey,
  Uint8List message,
  Uint8List signature, {
  PqSignatureAlgorithm? mlDsa,
  PqSlhDsaAlgorithm? slhDsa,
  bool offload = true,
}) {
  if (!_offloadTrust(offload, slhDsa)) {
    return Future.value(
      _trustVerify(publicKey, message, signature, mlDsa, slhDsa),
    );
  }
  return Isolate.run(
    () => _trustVerify(publicKey, message, signature, mlDsa, slhDsa),
  );
}

bool _offloadTrust(bool offload, PqSlhDsaAlgorithm? slhDsa) {
  if (!offload) return false;
  if (slhDsa != null) return true;
  return PqLattice.provider is PqPureDartLatticeProvider;
}

(Uint8List, Uint8List) _encapsulate(
  PqKemAlgorithm algorithm,
  Uint8List publicKey,
  Uint8List coins,
) {
  return PqLattice.provider.kemEncapsulate(algorithm, publicKey, nonce: coins);
}

Uint8List _decapsulate(
  PqKemAlgorithm algorithm,
  Uint8List secretKey,
  Uint8List ciphertext,
) {
  return PqLattice.provider.kemDecapsulate(algorithm, secretKey, ciphertext);
}

Uint8List _trustSign(
  Uint8List secretKey,
  Uint8List message,
  PqSignatureAlgorithm? mlDsa,
  PqSlhDsaAlgorithm? slhDsa,
) {
  if ((mlDsa == null) == (slhDsa == null)) {
    throw ArgumentError('Pass one trust algorithm');
  }
  if (mlDsa != null) {
    return PqSignaturePrimitives.sign(mlDsa, secretKey, message);
  }
  return PqSlhDsaPrimitives.sign(
    slhDsa!,
    secretKey,
    message,
    allowSlowSigning: !slhDsa.isFast,
  );
}

bool _trustVerify(
  Uint8List publicKey,
  Uint8List message,
  Uint8List signature,
  PqSignatureAlgorithm? mlDsa,
  PqSlhDsaAlgorithm? slhDsa,
) {
  if ((mlDsa == null) == (slhDsa == null)) {
    throw ArgumentError('Pass one trust algorithm');
  }
  if (mlDsa != null) {
    return PqSignaturePrimitives.verify(mlDsa, publicKey, message, signature);
  }
  return PqSlhDsaPrimitives.verify(slhDsa!, publicKey, message, signature);
}
