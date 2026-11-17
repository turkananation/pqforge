/// Incremental ML-KEM-768. The NTT stays in pqcrypto.
///
/// `ek_seed` is rho, the last 32 bytes of the FIPS encapsulation key.
/// `ek_vector` is `t`, the first 1152. `hek` for the braid is
/// SHA3-256(rho || t). FIPS 203 stores SHA3-256(t || rho). Those are not
/// the same input, so [PqcKem.kyber768.decapsulate] does not open a braid
/// ciphertext. This file does not call `encapsulate`.
library;

// pqcrypto does not export Indcpa. The braid needs the ciphertext split,
// and `u` does not depend on `t`. Importing the PKE is the whole adapter.
// ignore_for_file: implementation_imports

import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart' hide secureZero;
import 'package:pqcrypto/src/algos/kyber/indcpa.dart';
import 'package:zeroize/zeroize.dart';

const mlKem768EkVectorBytes = 1152;
const mlKem768Ct1Bytes = 960;
const mlKem768Ct2Bytes = 128;
const mlKem768PublicKeyBytes = 1184;
const mlKem768SecretKeyBytes = 2400;

KyberParams get _params => PqcKem.kyber768.params;

/// `(dk, ek_seed, ek_vector, hek)` with `hek = SHA3-256(ek_seed || ek_vector)`.
List<Uint8List> mlKem768KeyGenSync(Uint8List seed) {
  if (seed.length != 64) {
    throw ArgumentError.value(seed.length, 'seed', '64 bytes, d || z');
  }
  final (pk, sk) = PqcKem.kyber768.generateKeyPair(seed);
  if (pk.length != mlKem768PublicKeyBytes ||
      sk.length != mlKem768SecretKeyBytes) {
    throw StateError('pqcrypto returned an unexpected ML-KEM-768 key size');
  }
  final vector = Uint8List.sublistView(pk, 0, mlKem768EkVectorBytes);
  final rho = Uint8List.sublistView(pk, mlKem768EkVectorBytes);
  final hekInput = Uint8List(32 + mlKem768EkVectorBytes);
  hekInput.setRange(0, 32, rho);
  hekInput.setRange(32, hekInput.length, vector);
  final hek = sha3256(hekInput);
  secureZero(hekInput);
  final out = <Uint8List>[
    Uint8List.fromList(sk),
    Uint8List.fromList(rho),
    Uint8List.fromList(vector),
    hek,
  ];
  secureZero(sk);
  return out;
}

/// `(encaps_secret, ct1, shared_secret)`.
///
/// [hek] is the FO hash. The braid passes SHA3-256(rho || t). A caller that
/// passes SHA3-256(t || rho) is running FIPS encapsulation, not the braid.
/// `encaps_secret` is `m || r || hek` (96 bytes). `shared_secret` is K, before
/// `KDF_OK`.
List<Uint8List> mlKem768Encaps1Sync(
  Uint8List ekSeed,
  Uint8List hek,
  Uint8List coins,
) {
  _seed(ekSeed);
  _hek(hek);
  if (coins.length != 32) {
    throw ArgumentError.value(coins.length, 'coins', '32 bytes');
  }
  final kr = _coins(coins, hek);
  final secret = Uint8List(32);
  final r = Uint8List(32);
  try {
    secret.setRange(0, 32, kr);
    r.setRange(0, 32, Uint8List.sublistView(kr, 32));
    final pk = Uint8List(mlKem768PublicKeyBytes);
    pk.setRange(mlKem768EkVectorBytes, mlKem768PublicKeyBytes, ekSeed);
    final ct = Indcpa.encrypt(pk, coins, r, _params);
    if (ct.length != mlKem768Ct1Bytes + mlKem768Ct2Bytes) {
      throw StateError('Unexpected ML-KEM-768 ciphertext length');
    }
    final encaps = Uint8List(96);
    encaps.setRange(0, 32, coins);
    encaps.setRange(32, 64, r);
    encaps.setRange(64, 96, hek);
    return [
      encaps,
      Uint8List.fromList(Uint8List.sublistView(ct, 0, mlKem768Ct1Bytes)),
      Uint8List.fromList(secret),
    ];
  } finally {
    secureZero(kr);
    secureZero(secret);
    secureZero(r);
  }
}

/// `ct2`. Does not check [hek]. The braid checks SHA3-256(rho || t) first.
Uint8List mlKem768Encaps2Sync(
  Uint8List encapsSecret,
  Uint8List ekSeed,
  Uint8List ekVector,
) {
  if (encapsSecret.length != 96) {
    throw ArgumentError.value(encapsSecret.length, 'encapsSecret', '96 bytes');
  }
  _seed(ekSeed);
  if (ekVector.length != mlKem768EkVectorBytes) {
    throw ArgumentError.value(
      ekVector.length,
      'ekVector',
      '$mlKem768EkVectorBytes bytes',
    );
  }
  final message = Uint8List.sublistView(encapsSecret, 0, 32);
  final coins = Uint8List.sublistView(encapsSecret, 32, 64);
  final pk = Uint8List(mlKem768PublicKeyBytes);
  pk.setRange(0, mlKem768EkVectorBytes, ekVector);
  pk.setRange(mlKem768EkVectorBytes, mlKem768PublicKeyBytes, ekSeed);
  final ct = Indcpa.encrypt(pk, message, coins, _params);
  return Uint8List.fromList(Uint8List.sublistView(ct, mlKem768Ct1Bytes));
}

/// Spec-order decapsulation. The FO hash is SHA3-256(rho || t), recomputed
/// from the key, not the FIPS hash stored in the secret key.
Uint8List mlKem768DecapsSync(
  Uint8List decapsulationKey,
  Uint8List ct1,
  Uint8List ct2,
) {
  if (decapsulationKey.length != mlKem768SecretKeyBytes) {
    throw ArgumentError.value(
      decapsulationKey.length,
      'decapsulationKey',
      '$mlKem768SecretKeyBytes bytes',
    );
  }
  if (ct1.length != mlKem768Ct1Bytes) {
    throw ArgumentError.value(ct1.length, 'ct1', '$mlKem768Ct1Bytes bytes');
  }
  if (ct2.length != mlKem768Ct2Bytes) {
    throw ArgumentError.value(ct2.length, 'ct2', '$mlKem768Ct2Bytes bytes');
  }
  final pk = Uint8List.sublistView(
    decapsulationKey,
    mlKem768EkVectorBytes,
    mlKem768EkVectorBytes + mlKem768PublicKeyBytes,
  );
  final z = Uint8List.sublistView(
    decapsulationKey,
    mlKem768SecretKeyBytes - 32,
  );
  final ct = Uint8List(mlKem768Ct1Bytes + mlKem768Ct2Bytes);
  ct.setRange(0, mlKem768Ct1Bytes, ct1);
  ct.setRange(mlKem768Ct1Bytes, ct.length, ct2);
  final rho = Uint8List.sublistView(pk, mlKem768EkVectorBytes);
  final vector = Uint8List.sublistView(pk, 0, mlKem768EkVectorBytes);
  final hekInput = Uint8List(32 + mlKem768EkVectorBytes);
  hekInput.setRange(0, 32, rho);
  hekInput.setRange(32, hekInput.length, vector);
  final hek = sha3256(hekInput);
  secureZero(hekInput);

  Uint8List? message;
  Uint8List? kr;
  Uint8List? rejection;
  Uint8List? recomputed;
  try {
    message = Indcpa.decrypt(decapsulationKey, ct, _params);
    kr = _coins(message, hek);
    final secret = Uint8List.sublistView(kr, 0, 32);
    final coins = Uint8List.sublistView(kr, 32, 64);
    recomputed = Indcpa.encrypt(pk, message, coins, _params);
    rejection = _reject(z, ct);
    return _select(ct, recomputed, secret, rejection);
  } finally {
    if (message != null) secureZero(message);
    if (kr != null) secureZero(kr);
    if (rejection != null) secureZero(rejection);
    if (recomputed != null) secureZero(recomputed);
    secureZero(hek);
  }
}

Uint8List _coins(Uint8List message, Uint8List hek) {
  final input = Uint8List(64);
  input.setRange(0, 32, message);
  input.setRange(32, 64, hek);
  try {
    return sha3512(input);
  } finally {
    secureZero(input);
  }
}

Uint8List _reject(Uint8List z, Uint8List ciphertext) {
  final input = Uint8List(z.length + ciphertext.length);
  input.setRange(0, z.length, z);
  input.setRange(z.length, input.length, ciphertext);
  try {
    return Shake256.shake(input, 32);
  } finally {
    secureZero(input);
  }
}

Uint8List _select(
  Uint8List left,
  Uint8List right,
  Uint8List match,
  Uint8List miss,
) {
  var diff = left.length ^ right.length;
  final n = left.length < right.length ? left.length : right.length;
  for (var i = 0; i < n; i++) {
    diff |= left[i] ^ right[i];
  }
  final equalMask = (((diff | -diff) >> 31) & 0xFF) ^ 0xFF;
  final otherMask = equalMask ^ 0xFF;
  final out = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    out[i] = (match[i] & equalMask) | (miss[i] & otherMask);
  }
  return out;
}

void _seed(Uint8List ekSeed) {
  if (ekSeed.length != 32) {
    throw ArgumentError.value(ekSeed.length, 'ekSeed', '32 bytes');
  }
}

void _hek(Uint8List hek) {
  if (hek.length != 32) {
    throw ArgumentError.value(hek.length, 'hek', '32 bytes');
  }
}
