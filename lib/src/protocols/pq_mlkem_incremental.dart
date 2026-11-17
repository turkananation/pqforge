/// ML-KEM-768 as the braid's incremental KEM. Not FIPS encapsulation.
///
/// pqcrypto exposes key generation, encapsulation, and decapsulation. The
/// braid needs [keyGen], [encaps1], and [encaps2]. `ct1` is computed from
/// rho and the FO hash, before `t` arrives. The NTT is still pqcrypto's.
/// A full [PqcKem.kyber768.encapsulate] uses SHA3-256(t || rho) and is a
/// different protocol.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:zeroize/zeroize.dart';

import 'pq_mlkem_incremental_core.dart';
import 'pq_mlkem_incremental_stub.dart'
    if (dart.library.isolate) 'pq_mlkem_incremental_isolate.dart'
    as off;

/// One sampled encapsulation key, split the way the braid sends it.
final class MlKemIncrementalKeys {
  MlKemIncrementalKeys._(
    this.decapsulationKey,
    this.ekSeed,
    this.ekVector,
    this.hek,
  );

  /// FIPS 203 secret key, 2400 bytes. Wipe it. Do not serialize it into a
  /// session.
  final Uint8List decapsulationKey;

  /// rho. 32 bytes. The last 32 bytes of the FIPS encapsulation key.
  final Uint8List ekSeed;

  /// `t`. 1152 bytes. The first 1152 bytes of the FIPS encapsulation key.
  final Uint8List ekVector;

  /// SHA3-256(ek_seed || ek_vector). Not SHA3-256(t || rho).
  final Uint8List hek;

  /// Zeros [decapsulationKey].
  void wipe() => secureZero(decapsulationKey);
}

/// Result of [MlKemIncremental.encaps1]. The shared secret is K, not `KDF_OK`.
final class MlKemEncaps1Result {
  MlKemEncaps1Result._(this.encapsSecret, this.ct1, this.sharedSecret);

  /// `m || r || hek`. 96 bytes. Input to [MlKemIncremental.encaps2].
  final Uint8List encapsSecret;

  /// Compressed `u`. 960 bytes.
  final Uint8List ct1;

  /// ML-KEM shared secret K. The braid still runs `KDF_OK`.
  final Uint8List sharedSecret;

  /// Zeros [encapsSecret] and [sharedSecret].
  void wipe() {
    secureZero(encapsSecret);
    secureZero(sharedSecret);
  }
}

/// Encaps1 / Encaps2 / Decaps for ML-KEM-768.
abstract final class MlKemIncremental {
  static const ekSeedBytes = 32;
  static const hekBytes = 32;
  static const ekVectorBytes = mlKem768EkVectorBytes;
  static const ct1Bytes = mlKem768Ct1Bytes;
  static const ct2Bytes = mlKem768Ct2Bytes;
  static const headerBytes = ekSeedBytes + hekBytes;
  static const decapsulationKeyBytes = mlKem768SecretKeyBytes;

  /// [seed] is 64 bytes, `d || z`. Omitted seeds are drawn here.
  static Future<MlKemIncrementalKeys> keyGen({Uint8List? seed}) async {
    final owned = seed == null;
    if (seed != null && seed.length != 64) {
      throw ArgumentError.value(seed.length, 'seed', '64 bytes, d || z');
    }
    final material = seed ?? _random(64);
    try {
      final parts = await off.mlKem768KeyGenOff(material);
      return MlKemIncrementalKeys._(parts[0], parts[1], parts[2], parts[3]);
    } finally {
      if (owned) secureZero(material);
    }
  }

  /// [coins] is the 32-byte FO message `m`. [hek] is the hash Encaps1 mixes
  /// into `G(m || hek)`. The braid's value is [MlKemIncrementalKeys.hek].
  static Future<MlKemEncaps1Result> encaps1({
    required Uint8List ekSeed,
    required Uint8List hek,
    Uint8List? coins,
  }) async {
    final owned = coins == null;
    if (coins != null && coins.length != 32) {
      throw ArgumentError.value(coins.length, 'coins', '32 bytes');
    }
    final message = coins ?? _random(32);
    try {
      final parts = await off.mlKem768Encaps1Off(ekSeed, hek, message);
      return MlKemEncaps1Result._(parts[0], parts[1], parts[2]);
    } finally {
      if (owned) secureZero(message);
    }
  }

  /// Finishes `ct2` from an [encaps1] secret and the noisy vector.
  static Future<Uint8List> encaps2({
    required Uint8List encapsSecret,
    required Uint8List ekSeed,
    required Uint8List ekVector,
  }) => off.mlKem768Encaps2Off(encapsSecret, ekSeed, ekVector);

  /// Decapsulates with SHA3-256(rho || t). Not [PqcKem.kyber768.decapsulate].
  static Future<Uint8List> decaps({
    required Uint8List decapsulationKey,
    required Uint8List ct1,
    required Uint8List ct2,
  }) => off.mlKem768DecapsOff(decapsulationKey, ct1, ct2);

  static Uint8List _random(int n) {
    final out = Uint8List(n);
    final random = Random.secure();
    for (var i = 0; i < n; i++) {
      out[i] = random.nextInt(256);
    }
    return out;
  }
}
