/// Sparse Post-Quantum Ratchet scaffold. The braid is not implemented.
///
/// The Triple Ratchet is this protocol beside [DoubleRatchet]. It needs
/// the ML-KEM Braid's incremental interface. pqcrypto exposes key
/// generation, encapsulation, and decapsulation, not that split.
/// [TripleRatchet.initiate] throws. A 1216-byte X-Wing key is rejected
/// by [RatchetPublicKey] before the throw.
library;

import '../exceptions/pqforge_exception.dart';
import 'pq_ratchet_types.dart';

/// The braid's KEM. Not X-Wing.
enum SpqrKem {
  /// ML-KEM-768, as the braid specifies. Not a one-shot encapsulation
  /// on every message, and not X-Wing.
  mlKem768,
}

/// Triple Ratchet entry point. The session type lands with the braid.
abstract final class TripleRatchet {
  /// Throws. Does not encapsulate, and does not start a [DoubleRatchet].
  static Future<Never> initiate({
    required SharedSecret32 sharedSecret,
    required RatchetPublicKey remoteRatchetKey,
    SpqrKem kem = SpqrKem.mlKem768,
  }) async {
    PqRatchetSecrets.copy32('sharedSecret', sharedSecret.bytes);
    PqRatchetSecrets.copy32('remoteRatchetKey', remoteRatchetKey.bytes);
    if (kem != SpqrKem.mlKem768) {
      throw ArgumentError.value(kem, 'kem', 'the braid is ML-KEM-768');
    }
    throw const PqForgeException(
      'The Sparse Post-Quantum Ratchet is not implemented. '
      'pqcrypto does not expose the ML-KEM Braid incremental interface. '
      'Use DoubleRatchet until that interface exists.',
    );
  }
}
