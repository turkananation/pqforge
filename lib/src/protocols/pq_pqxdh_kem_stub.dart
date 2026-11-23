/// ML-KEM and bundle-trust signatures for PQXDH on this isolate.
/// dart2wasm has no `dart:isolate`.
library;

import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_lattice_provider.dart';
import '../primitives/pq_primitives.dart';

/// Encapsulates to [algorithm]. [coins] is the 32-byte `m`.
Future<(Uint8List, Uint8List)> pqxdhKemEncapsulate(
  Uint8List publicKey,
  Uint8List coins, {
  PqKemAlgorithm algorithm = PqKemAlgorithm.mlKem1024,
  bool offload = true,
}) async {
  return PqLattice.provider.kemEncapsulate(algorithm, publicKey, nonce: coins);
}

/// Decapsulates [algorithm].
Future<Uint8List> pqxdhKemDecapsulate(
  Uint8List secretKey,
  Uint8List ciphertext, {
  PqKemAlgorithm algorithm = PqKemAlgorithm.mlKem1024,
  bool offload = true,
}) async {
  return PqLattice.provider.kemDecapsulate(algorithm, secretKey, ciphertext);
}

/// Signs the bundle trust message. An `s` set is allowed: the caller named it.
Future<Uint8List> pqxdhTrustSign(
  Uint8List secretKey,
  Uint8List message, {
  PqSignatureAlgorithm? mlDsa,
  PqSlhDsaAlgorithm? slhDsa,
  bool offload = true,
}) async {
  return _trustSign(secretKey, message, mlDsa, slhDsa);
}

/// Verifies the bundle trust message.
Future<bool> pqxdhTrustVerify(
  Uint8List publicKey,
  Uint8List message,
  Uint8List signature, {
  PqSignatureAlgorithm? mlDsa,
  PqSlhDsaAlgorithm? slhDsa,
  bool offload = true,
}) async {
  return _trustVerify(publicKey, message, signature, mlDsa, slhDsa);
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
