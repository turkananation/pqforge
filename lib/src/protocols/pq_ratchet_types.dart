/// Fixed-length secrets and X25519 ratchet keys.
///
/// A 1216-byte X-Wing public key does not construct any of these. Neither
/// does an ML-KEM private key. The lengths are the protocol boundary.
library;

import 'dart:typed_data';

import 'package:zeroize/zeroize.dart';

import '../algorithms/pq_algorithms.dart';
import '../exceptions/pqforge_exception.dart';
import '../hybrid/pq_classical_provider.dart';

/// ML-KEM private-key sizes (FIPS 203). None of them is a ratchet secret.
const mlKemPrivateKeyLengths = <int>{1632, 2400, 3168};

/// Copies a 32-byte secret and refuses an expanded ML-KEM private key.
abstract final class PqRatchetSecrets {
  /// [name] is the field name in the error.
  static Uint8List copy32(String name, Uint8List bytes) {
    if (mlKemPrivateKeyLengths.contains(bytes.length)) {
      throw PqForgeException(
        'An expanded ML-KEM private key cannot be used as $name',
      );
    }
    if (bytes.length == 1216) {
      throw ArgumentError.value(
        bytes.length,
        name,
        'an X-Wing public key is not a 32-byte ratchet value',
      );
    }
    requireLength(name, bytes, 32);
    return Uint8List.fromList(bytes);
  }
}

/// 32-byte root secret. Not a public key, not a ciphertext, not a transcript.
final class SharedSecret32 {
  SharedSecret32(Uint8List bytes)
    : bytes = PqRatchetSecrets.copy32('sharedSecret', bytes);

  /// Exactly 32 bytes. The caller does not own this copy.
  final Uint8List bytes;

  static const length = 32;
}

/// X25519 ratchet public key. 32 bytes. Not an X-Wing key.
final class RatchetPublicKey {
  RatchetPublicKey(Uint8List bytes)
    : bytes = PqRatchetSecrets.copy32('ratchetPublicKey', bytes);

  RatchetPublicKey._view(this.bytes);

  /// View of an existing 32-byte region. The buffer must outlive this key.
  factory RatchetPublicKey.view(Uint8List bytes) {
    requireLength('ratchetPublicKey', bytes, 32);
    return RatchetPublicKey._view(bytes);
  }

  final Uint8List bytes;

  static const length = 32;
}

/// X25519 ratchet key pair. [secretKey] is 32 bytes and is the scalar seed.
final class RatchetKeyPair {
  RatchetKeyPair({required Uint8List secretKey, required this.publicKey})
    : secretKey = PqRatchetSecrets.copy32('ratchetSecretKey', secretKey);

  RatchetKeyPair._(this.secretKey, this.publicKey);

  /// Fresh X25519 pair from [PqClassical]. [seed] is optional and 32 bytes.
  static Future<RatchetKeyPair> generate({Uint8List? seed}) async {
    if (seed != null) requireLength('seed', seed, 32);
    final pair = await PqClassical.provider.x25519GenerateKeyPair(seed: seed);
    try {
      return RatchetKeyPair._(
        Uint8List.fromList(pair.secretKey),
        RatchetPublicKey(pair.publicKey),
      );
    } finally {
      secureZero(pair.secretKey);
    }
  }

  final Uint8List secretKey;
  final RatchetPublicKey publicKey;

  /// Wipes [secretKey]. The public key stays.
  void wipe() => secureZero(secretKey);
}
