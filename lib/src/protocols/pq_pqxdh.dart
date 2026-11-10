/// PQXDH scaffold. The handshake is not implemented.
///
/// Signal PQXDH revision 3 needs XEdDSA. This package has Ed25519, and
/// Ed25519 is not XEdDSA. [Pqxdh.initiate] and [Pqxdh.accept] throw until
/// that primitive exists and has its own vectors. The bundle type is live
/// so a 1216-byte X-Wing key cannot be passed as a PQXDH key.
library;

import 'dart:typed_data';

import '../exceptions/pqforge_exception.dart';
import 'pq_double_ratchet.dart';
import 'pq_ratchet_types.dart';

/// The KEM named by the PQXDH specification's example. Not X-Wing.
enum PqxdhKem {
  /// CRYSTALS-Kyber-1024, as in the specification's info string.
  /// The public key is 1568 bytes. ML-KEM-1024 has the same size.
  kyber1024(publicKeyBytes: 1568);

  const PqxdhKem({required this.publicKeyBytes});

  final int publicKeyBytes;
}

/// Bob's prekey bundle. The caller fetched it. There is no server here.
final class PqxdhBundle {
  PqxdhBundle({
    required RatchetPublicKey identityKey,
    required RatchetPublicKey signedPrekey,
    required Uint8List signedPrekeySignature,
    RatchetPublicKey? oneTimePrekey,
    required Uint8List kemPublicKey,
    this.kem = PqxdhKem.kyber1024,
  }) : identityKey = RatchetPublicKey(identityKey.bytes),
       signedPrekey = RatchetPublicKey(signedPrekey.bytes),
       signedPrekeySignature = _signature(signedPrekeySignature),
       oneTimePrekey = oneTimePrekey == null
           ? null
           : RatchetPublicKey(oneTimePrekey.bytes),
       kemPublicKey = _kemKey(kem, kemPublicKey);

  /// X25519 identity public key. XEdDSA-capable when the handshake exists.
  final RatchetPublicKey identityKey;

  /// Signed prekey public key.
  final RatchetPublicKey signedPrekey;

  /// 64-byte XEdDSA signature over [signedPrekey]. Not checked yet.
  final Uint8List signedPrekeySignature;

  /// Optional one-time prekey.
  final RatchetPublicKey? oneTimePrekey;

  /// Post-quantum prekey. 1568 bytes for [PqxdhKem.kyber1024].
  final Uint8List kemPublicKey;

  final PqxdhKem kem;
}

/// What a finished handshake will return. Implemented with the handshake.
abstract interface class PqxdhResult {
  /// 32-byte secret. The ratchet is already started from it.
  SharedSecret32 get sharedSecret;

  /// [DoubleRatchet] in the initiator or responder role.
  DoubleRatchet get ratchet;

  /// Alice's first message. Null for the responder.
  DoubleRatchetMessage? get initialMessage;
}

/// PQXDH entry points. Both throw. The types are ready for the next release.
abstract final class Pqxdh {
  /// Alice. Throws. Does not encapsulate and does not return a secret.
  static Future<PqxdhResult> initiate({
    required RatchetKeyPair identityKey,
    required PqxdhBundle bundle,
    PqxdhKem kem = PqxdhKem.kyber1024,
  }) async {
    if (kem != bundle.kem) {
      throw ArgumentError.value(kem, 'kem', 'does not match the bundle');
    }
    if (identityKey.publicKey.bytes.length != RatchetPublicKey.length) {
      throw ArgumentError.value(
        identityKey.publicKey.bytes.length,
        'identityKey',
        'expected 32 bytes',
      );
    }
    throw const PqForgeException(
      'PQXDH is not implemented. It needs XEdDSA, and Ed25519 is not XEdDSA. '
      'Pass a 32-byte shared secret to DoubleRatchet.initiate instead.',
    );
  }

  /// Bob. Throws. Does not derive SK.
  static Future<PqxdhResult> accept({
    required RatchetKeyPair identityKey,
    required RatchetKeyPair signedPrekey,
    required PqxdhBundle bundle,
    required DoubleRatchetMessage initialMessage,
    PqxdhKem kem = PqxdhKem.kyber1024,
  }) async {
    if (kem != bundle.kem) {
      throw ArgumentError.value(kem, 'kem', 'does not match the bundle');
    }
    if (identityKey.secretKey.length != 32 ||
        signedPrekey.secretKey.length != 32) {
      throw ArgumentError('PQXDH identity keys are 32 bytes');
    }
    if (initialMessage.bytes.isEmpty) {
      throw const PqForgeException('PQXDH initial message is empty');
    }
    throw const PqForgeException(
      'PQXDH is not implemented. It needs XEdDSA, and Ed25519 is not XEdDSA.',
    );
  }
}

Uint8List _signature(Uint8List signature) {
  if (signature.length == 1216) {
    throw ArgumentError.value(
      signature.length,
      'signedPrekeySignature',
      'an X-Wing public key is not an XEdDSA signature',
    );
  }
  if (signature.length != 64) {
    throw ArgumentError.value(
      signature.length,
      'signedPrekeySignature',
      'expected 64 bytes',
    );
  }
  return Uint8List.fromList(signature);
}

Uint8List _kemKey(PqxdhKem kem, Uint8List key) {
  if (key.length == 1216) {
    throw ArgumentError.value(
      key.length,
      'kemPublicKey',
      'an X-Wing public key is not a PQXDH KEM key',
    );
  }
  if (key.length != kem.publicKeyBytes) {
    throw ArgumentError.value(
      key.length,
      'kemPublicKey',
      'expected ${kem.publicKeyBytes} bytes',
    );
  }
  return Uint8List.fromList(key);
}
