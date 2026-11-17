/// PQXDH revision 3 on Curve25519.
///
/// Specification: [The PQXDH Key Agreement Protocol](https://signal.org/docs/specifications/pqxdh/),
/// revision 3, 2023-05-24, last updated 2024-01-23. The document is in the
/// public domain. This is an independent implementation. It is not Signal
/// Messenger and it does not speak libsignal's protobuf wire format.
///
/// Profile, fixed so two callers of the defaults agree:
///
/// * curve: Curve25519. `EncodeEC` is the raw 32-byte RFC 7748 u-coordinate.
///   That is the message [Pqxdh.signedPrekeyAuthentic] already verified, and
///   the message libsignal passes to `PrivateKey::calculate_signature`.
/// * hash: SHA-512. HKDF salt is 64 zero bytes. Output is 32 bytes.
/// * KEM: ML-KEM-1024 (FIPS 203) through `pqcrypto`. The spec's example
///   string names CRYSTALS-Kyber-1024. These bytes are ML-KEM, so the HKDF
///   info names `ML-KEM-1024`. Round-3 Kyber is not implemented.
/// * `EncodeKEM` is the raw 1568-byte encapsulation key. It is disjoint
///   from `EncodeEC` by length. ML-KEM does not bind that key into the
///   ciphertext, so it is appended to the AEAD associated data.
/// * AEAD: AES-256-GCM, or ChaCha20-Poly1305 when [PqFipsMode] is off.
///   The key is SK. The nonce is 12 zero bytes. SK encrypts this one
///   message and is not reused.
///
/// `F` is 32 bytes of `0xFF`. With a one-time prekey:
///
/// ```text
/// SK = HKDF(F || DH1 || DH2 || DH3 || DH4 || SS)
/// ```
///
/// Without one, `DH4` is absent. Not X-Wing. Not a FIPS handshake.
/// [TripleRatchet] is still not this protocol.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart' as pqc;
import 'package:zeroize/zeroize.dart';

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_fips.dart';
import '../algorithms/pq_lattice_provider.dart';
import '../cipher/pq_cipher_suite.dart';
import '../exceptions/pqforge_exception.dart';
import '../hybrid/pq_ed25519.dart';
import '../hybrid/pqforge_hybrid_key_agreement.dart';
import '../primitives/pq_primitives.dart';
import 'pq_double_ratchet.dart';
import 'pq_pqxdh_kem.dart';
import 'pq_ratchet_types.dart';

/// The KEM this profile runs. Not X-Wing, and not round-3 Kyber.
enum PqxdhKem {
  /// ML-KEM-1024. Public key 1568 bytes, ciphertext 1568, secret 3168.
  /// The enum name is the name this scaffold already shipped.
  kyber1024(publicKeyBytes: 1568, ciphertextBytes: 1568, secretKeyBytes: 3168);

  const PqxdhKem({
    required this.publicKeyBytes,
    required this.ciphertextBytes,
    required this.secretKeyBytes,
  });

  final int publicKeyBytes;
  final int ciphertextBytes;
  final int secretKeyBytes;
}

/// Bob's prekey bundle. The caller fetched it. There is no server here.
final class PqxdhBundle {
  PqxdhBundle({
    required RatchetPublicKey identityKey,
    required RatchetPublicKey signedPrekey,
    required Uint8List signedPrekeySignature,
    required Uint8List kemPublicKeySignature,
    RatchetPublicKey? oneTimePrekey,
    required Uint8List kemPublicKey,
    this.kem = PqxdhKem.kyber1024,
  }) : identityKey = RatchetPublicKey(identityKey.bytes),
       signedPrekey = RatchetPublicKey(signedPrekey.bytes),
       signedPrekeySignature = _signature(signedPrekeySignature),
       kemPublicKeySignature = _signature(
         kemPublicKeySignature,
         name: 'kemPublicKeySignature',
       ),
       oneTimePrekey = oneTimePrekey == null
           ? null
           : RatchetPublicKey(oneTimePrekey.bytes),
       kemPublicKey = _kemKey(kem, kemPublicKey);

  /// X25519 identity public key.
  final RatchetPublicKey identityKey;

  /// Signed prekey public key.
  final RatchetPublicKey signedPrekey;

  /// XEdDSA over the 32-byte signed prekey. 64 bytes.
  final Uint8List signedPrekeySignature;

  /// XEdDSA over the ML-KEM encapsulation key. 64 bytes.
  final Uint8List kemPublicKeySignature;

  /// Optional one-time curve prekey.
  final RatchetPublicKey? oneTimePrekey;

  /// ML-KEM-1024 encapsulation key. 1568 bytes.
  final Uint8List kemPublicKey;

  final PqxdhKem kem;
}

/// Secrets Bob keeps. The bundle is what he publishes.
final class PqxdhPrekeys {
  PqxdhPrekeys({
    required this.identityKey,
    required this.signedPrekey,
    required this.oneTimePrekey,
    required Uint8List kemSecretKey,
    required this.bundle,
  }) : kemSecretKey = Uint8List.fromList(kemSecretKey);

  /// Identity key. Also the XEdDSA signing key for the prekeys.
  final RatchetKeyPair identityKey;

  /// Signed prekey. This is the Double Ratchet's first remote key.
  final RatchetKeyPair signedPrekey;

  /// Present when [Pqxdh.publish] was asked for a one-time prekey.
  final RatchetKeyPair? oneTimePrekey;

  /// ML-KEM-1024 decapsulation key. 3168 bytes. Not a ratchet secret.
  final Uint8List kemSecretKey;

  /// The public bundle.
  final PqxdhBundle bundle;

  /// Wipes the X25519 secrets and the ML-KEM decapsulation key.
  void wipe() {
    identityKey.wipe();
    signedPrekey.wipe();
    oneTimePrekey?.wipe();
    secureZero(kemSecretKey);
  }
}

/// Alice's first message. Version 1 is ML-KEM-1024 on Curve25519.
///
/// ```text
/// "PQX1" || version=1 || flags || IK_A(32) || EK_A(32) || CT(1568) || AEAD
/// ```
///
/// `flags` bit 0 means a one-time curve prekey was used. The AEAD nonce is
/// not on the wire. It is 12 zero bytes.
final class PqxdhMessage {
  PqxdhMessage._(this.bytes)
    : aliceIdentity = Uint8List.sublistView(bytes, 6, 38),
      ephemeralKey = Uint8List.sublistView(bytes, 38, 70),
      kemCiphertext = Uint8List.sublistView(bytes, 70, _kemCiphertextEnd),
      sealed = Uint8List.sublistView(bytes, _kemCiphertextEnd);

  /// Parses [bytes]. The fields are views.
  factory PqxdhMessage.parse(Uint8List bytes) {
    if (bytes.length < _kemCiphertextEnd + 16) {
      throw const PqForgeException('PQXDH initial message is truncated');
    }
    if (bytes[0] != 0x50 ||
        bytes[1] != 0x51 ||
        bytes[2] != 0x58 ||
        bytes[3] != 0x31) {
      throw const PqForgeException('Not a PQXDH initial message');
    }
    if (bytes[4] != 1) {
      throw const PqForgeException('Unknown PQXDH message version');
    }
    if (bytes[5] > 1) {
      throw const PqForgeException('Unknown PQXDH message flags');
    }
    return PqxdhMessage._(bytes);
  }

  static const _header = 70;
  static const _kemCiphertextEnd = _header + 1568;

  /// Owned by [Pqxdh.initiate]. Viewed by [parse].
  final Uint8List bytes;

  /// Alice's identity public key. A view.
  final Uint8List aliceIdentity;

  /// Alice's handshake ephemeral public key. A view. Not her ratchet key.
  final Uint8List ephemeralKey;

  /// ML-KEM-1024 ciphertext. A view.
  final Uint8List kemCiphertext;

  /// `ciphertext || tag` under SK. A view.
  final Uint8List sealed;

  /// Whether Alice used Bob's one-time curve prekey.
  bool get usedOneTimePrekey => bytes[5] == 1;
}

/// A finished handshake.
final class PqxdhResult {
  PqxdhResult({
    required this.sharedSecret,
    required this.ratchet,
    required Uint8List plaintext,
    required this.initialMessage,
  }) : plaintext = Uint8List.fromList(plaintext);

  /// 32-byte SK. The ratchet already holds its own copy. Wipe this one
  /// when the caller is done with it.
  final SharedSecret32 sharedSecret;

  /// [DoubleRatchet] started from SK. Alice can [DoubleRatchet.seal].
  /// Bob can [DoubleRatchet.open] her next ratchet message, not this one.
  /// The initial plaintext was encrypted under SK, not under a message key.
  final DoubleRatchet ratchet;

  /// The bytes Alice encrypted under SK.
  final Uint8List plaintext;

  /// Alice's message. Null on the accepting side.
  final PqxdhMessage? initialMessage;
}

/// PQXDH. [publish] makes a bundle. [initiate] and [accept] derive SK.
abstract final class Pqxdh {
  /// Application id used when the caller does not pass one. Eight bytes,
  /// no underscore.
  static const defaultInfo = 'pqforge01';

  /// The three parameter names joined into the HKDF info after the
  /// application id and an underscore.
  static const hkdfParameters = 'CURVE25519_SHA-512_ML-KEM-1024';

  /// Whether [bundle]'s signed prekey was signed by its identity key.
  ///
  /// The message is the 32-byte signed-prekey public key.
  static bool signedPrekeyAuthentic(PqxdhBundle bundle) {
    return PqXeddsa.verify(
      publicKey: bundle.identityKey.bytes,
      message: bundle.signedPrekey.bytes,
      signature: bundle.signedPrekeySignature,
    );
  }

  /// Whether [bundle]'s ML-KEM key was signed by its identity key.
  ///
  /// The message is the raw encapsulation key.
  static bool kemPrekeyAuthentic(PqxdhBundle bundle) {
    return PqXeddsa.verify(
      publicKey: bundle.identityKey.bytes,
      message: bundle.kemPublicKey,
      signature: bundle.kemPublicKeySignature,
    );
  }

  /// `EncodeEC(IK_A) || EncodeEC(IK_B) || EncodeKEM(PQPK_B) || extra`.
  ///
  /// [extra] is the optional associated data the specification allows
  /// (usernames, certificates). Both sides must pass the same bytes.
  static Uint8List associatedData({
    required Uint8List aliceIdentity,
    required Uint8List bobIdentity,
    required Uint8List kemPublicKey,
    Uint8List? extra,
  }) {
    requireLength('aliceIdentity', aliceIdentity, 32);
    requireLength('bobIdentity', bobIdentity, 32);
    if (kemPublicKey.length == 1216) {
      throw ArgumentError.value(
        kemPublicKey.length,
        'kemPublicKey',
        'an X-Wing public key is not a PQXDH KEM key',
      );
    }
    requireLength(
      'kemPublicKey',
      kemPublicKey,
      PqxdhKem.kyber1024.publicKeyBytes,
    );
    final tail = extra ?? Uint8List(0);
    final out = Uint8List(64 + kemPublicKey.length + tail.length);
    out.setRange(0, 32, aliceIdentity);
    out.setRange(32, 64, bobIdentity);
    out.setRange(64, 64 + kemPublicKey.length, kemPublicKey);
    out.setRange(64 + kemPublicKey.length, out.length, tail);
    return out;
  }

  /// Bob. Generates an identity key when [identityKey] is omitted.
  ///
  /// [kemSeed] is 64 bytes (`d || z`) when the caller needs a reproducible
  /// ML-KEM key. [signatureRandomness] is the 64-byte XEdDSA `Z` for both
  /// prekey signatures. Production callers omit both.
  static Future<PqxdhPrekeys> publish({
    RatchetKeyPair? identityKey,
    bool oneTimePrekey = false,
    Uint8List? identitySeed,
    Uint8List? signedPrekeySeed,
    Uint8List? oneTimePrekeySeed,
    Uint8List? kemSeed,
    Uint8List? signatureRandomness,
    PqxdhKem kem = PqxdhKem.kyber1024,
  }) async {
    if (kem != PqxdhKem.kyber1024) {
      throw ArgumentError.value(kem, 'kem', 'PQXDH here is ML-KEM-1024');
    }
    if (identityKey != null && identitySeed != null) {
      throw ArgumentError('Pass identityKey or identitySeed, not both');
    }
    final identity =
        identityKey ?? await RatchetKeyPair.generate(seed: identitySeed);
    final signedPrekey = await RatchetKeyPair.generate(seed: signedPrekeySeed);
    final oneTime = oneTimePrekey
        ? await RatchetKeyPair.generate(seed: oneTimePrekeySeed)
        : null;
    final randomness = signatureRandomness == null
        ? null
        : _copyRandomness(signatureRandomness);
    final (kemPublic, kemSecret) = PqLattice.provider.kemGenerateKeyPair(
      PqKemAlgorithm.mlKem1024,
      seed: kemSeed,
    );
    try {
      final spkSignature = PqXeddsa.sign(
        secretKey: identity.secretKey,
        message: signedPrekey.publicKey.bytes,
        randomness: randomness,
      );
      final kemSignature = PqXeddsa.sign(
        secretKey: identity.secretKey,
        message: kemPublic,
        randomness: randomness ?? PqBytes.randomBytes(PqXeddsa.randomnessBytes),
      );
      return PqxdhPrekeys(
        identityKey: identity,
        signedPrekey: signedPrekey,
        oneTimePrekey: oneTime,
        kemSecretKey: kemSecret,
        bundle: PqxdhBundle(
          identityKey: identity.publicKey,
          signedPrekey: signedPrekey.publicKey,
          signedPrekeySignature: spkSignature,
          kemPublicKeySignature: kemSignature,
          oneTimePrekey: oneTime?.publicKey,
          kemPublicKey: kemPublic,
          kem: kem,
        ),
      );
    } finally {
      secureZero(kemSecret);
      if (randomness != null) secureZero(randomness);
    }
  }

  /// Alice. Verifies both prekey signatures, encapsulates, derives SK,
  /// encrypts [plaintext], and starts a [DoubleRatchet].
  ///
  /// A bad signature throws [PqForgeException] and returns nothing.
  /// [info] is ASCII, at least 8 characters, with no space and no `_`.
  /// [kemCoins] is the 32-byte ML-KEM `m`. [ephemeralSeed] fixes `EK_A`.
  static Future<PqxdhResult> initiate({
    required RatchetKeyPair identityKey,
    required PqxdhBundle bundle,
    Uint8List? plaintext,
    String info = defaultInfo,
    Uint8List? extraAssociatedData,
    Uint8List? ephemeralSeed,
    Uint8List? kemCoins,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
    PqxdhKem kem = PqxdhKem.kyber1024,
  }) async {
    PqFipsMode.requireApprovedSuite(suite);
    if (kem != bundle.kem || kem != PqxdhKem.kyber1024) {
      throw ArgumentError.value(kem, 'kem', 'does not match the bundle');
    }
    if (identityKey.publicKey.bytes.length != RatchetPublicKey.length) {
      throw ArgumentError.value(
        identityKey.publicKey.bytes.length,
        'identityKey',
        'expected 32 bytes',
      );
    }
    final infoBytes = _hkdfInfo(info);
    if (!signedPrekeyAuthentic(bundle) || !kemPrekeyAuthentic(bundle)) {
      throw const PqForgeException(
        'PQXDH prekey signature is not valid. No secret was derived.',
      );
    }
    final ephemeral = await RatchetKeyPair.generate(seed: ephemeralSeed);
    final coins = kemCoins == null
        ? PqBytes.randomBytes(32)
        : _copy32('kemCoins', kemCoins);
    final plain = plaintext ?? Uint8List(0);
    Uint8List? dh1, dh2, dh3, dh4, ss, ikm, sk;
    try {
      final encapsulated = await pqxdhKemEncapsulate(
        bundle.kemPublicKey,
        coins,
      );
      final ciphertext = encapsulated.$1;
      ss = encapsulated.$2;
      if (ciphertext.length != kem.ciphertextBytes || ss.length != 32) {
        throw const PqForgeException(
          'ML-KEM encapsulation returned a bad size',
        );
      }
      dh1 = await _dh(identityKey.secretKey, bundle.signedPrekey.bytes);
      dh2 = await _dh(ephemeral.secretKey, bundle.identityKey.bytes);
      dh3 = await _dh(ephemeral.secretKey, bundle.signedPrekey.bytes);
      final oneTime = bundle.oneTimePrekey;
      if (oneTime != null) {
        dh4 = await _dh(ephemeral.secretKey, oneTime.bytes);
      }
      ikm = _ikm(dh1, dh2, dh3, dh4, ss);
      sk = _hkdf32(ikm, infoBytes);
      final ad = associatedData(
        aliceIdentity: identityKey.publicKey.bytes,
        bobIdentity: bundle.identityKey.bytes,
        kemPublicKey: bundle.kemPublicKey,
        extra: extraAssociatedData,
      );
      final sealed = _seal(suite, sk, plain, ad);
      final message = _encodeMessage(
        aliceIdentity: identityKey.publicKey.bytes,
        ephemeralKey: ephemeral.publicKey.bytes,
        kemCiphertext: ciphertext,
        sealed: sealed,
        oneTime: oneTime != null,
      );
      final secret = SharedSecret32(sk);
      final ratchet = await DoubleRatchet.initiate(
        sharedSecret: secret,
        remoteRatchetKey: bundle.signedPrekey,
        suite: suite,
      );
      return PqxdhResult(
        sharedSecret: secret,
        ratchet: ratchet,
        plaintext: plain,
        initialMessage: message,
      );
    } finally {
      ephemeral.wipe();
      secureZero(coins);
      _wipeAll([dh1, dh2, dh3, dh4, ss, ikm, sk]);
    }
  }

  /// Bob. [initialMessage] is what Alice sent. [kemSecretKey] is the
  /// ML-KEM-1024 decapsulation key for the prekey she encapsulated to.
  /// [oneTimePrekey] is required exactly when her message used one.
  static Future<PqxdhResult> accept({
    required RatchetKeyPair identityKey,
    required RatchetKeyPair signedPrekey,
    required Uint8List kemSecretKey,
    RatchetKeyPair? oneTimePrekey,
    required PqxdhMessage initialMessage,
    String info = defaultInfo,
    Uint8List? extraAssociatedData,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
    PqxdhKem kem = PqxdhKem.kyber1024,
  }) async {
    PqFipsMode.requireApprovedSuite(suite);
    if (kem != PqxdhKem.kyber1024) {
      throw ArgumentError.value(kem, 'kem', 'PQXDH here is ML-KEM-1024');
    }
    if (identityKey.secretKey.length != 32 ||
        signedPrekey.secretKey.length != 32) {
      throw ArgumentError('PQXDH identity keys are 32 bytes');
    }
    if (kemSecretKey.length == 1216) {
      throw ArgumentError.value(
        kemSecretKey.length,
        'kemSecretKey',
        'an X-Wing public key is not an ML-KEM secret key',
      );
    }
    requireLength('kemSecretKey', kemSecretKey, kem.secretKeyBytes);
    if (initialMessage.bytes.isEmpty) {
      throw const PqForgeException('PQXDH initial message is empty');
    }
    final usedOneTime = initialMessage.usedOneTimePrekey;
    if (usedOneTime != (oneTimePrekey != null)) {
      throw const PqForgeException(
        'PQXDH one-time prekey does not match the initial message',
      );
    }
    final infoBytes = _hkdfInfo(info);
    final kemPublic = Uint8List.sublistView(
      kemSecretKey,
      1536,
      1536 + kem.publicKeyBytes,
    );
    Uint8List? dh1, dh2, dh3, dh4, ss, ikm, sk;
    try {
      ss = await pqxdhKemDecapsulate(
        kemSecretKey,
        initialMessage.kemCiphertext,
      );
      if (ss.length != 32) {
        throw const PqForgeException(
          'ML-KEM decapsulation returned a bad size',
        );
      }
      dh1 = await _dh(signedPrekey.secretKey, initialMessage.aliceIdentity);
      dh2 = await _dh(identityKey.secretKey, initialMessage.ephemeralKey);
      dh3 = await _dh(signedPrekey.secretKey, initialMessage.ephemeralKey);
      if (usedOneTime) {
        dh4 = await _dh(oneTimePrekey!.secretKey, initialMessage.ephemeralKey);
      }
      ikm = _ikm(dh1, dh2, dh3, dh4, ss);
      sk = _hkdf32(ikm, infoBytes);
      final ad = associatedData(
        aliceIdentity: initialMessage.aliceIdentity,
        bobIdentity: identityKey.publicKey.bytes,
        kemPublicKey: kemPublic,
        extra: extraAssociatedData,
      );
      final plain = _open(suite, sk, initialMessage.sealed, ad);
      final secret = SharedSecret32(sk);
      final ratchet = DoubleRatchet.accept(
        sharedSecret: secret,
        ratchetKey: signedPrekey,
        suite: suite,
      );
      return PqxdhResult(
        sharedSecret: secret,
        ratchet: ratchet,
        plaintext: plain,
        initialMessage: null,
      );
    } finally {
      _wipeAll([dh1, dh2, dh3, dh4, ss, ikm, sk]);
    }
  }
}

Uint8List _signature(
  Uint8List signature, {
  String name = 'signedPrekeySignature',
}) {
  if (signature.length == 1216) {
    throw ArgumentError.value(
      signature.length,
      name,
      'an X-Wing public key is not an XEdDSA signature',
    );
  }
  if (signature.length != 64) {
    throw ArgumentError.value(signature.length, name, 'expected 64 bytes');
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

Uint8List _copy32(String name, Uint8List bytes) {
  requireLength(name, bytes, 32);
  return Uint8List.fromList(bytes);
}

Uint8List _copyRandomness(Uint8List bytes) {
  requireLength('signatureRandomness', bytes, PqXeddsa.randomnessBytes);
  return Uint8List.fromList(bytes);
}

Uint8List _hkdfInfo(String info) {
  if (info.length < 8) {
    throw ArgumentError.value(
      info.length,
      'info',
      'expected at least 8 characters',
    );
  }
  for (final unit in info.codeUnits) {
    final underscore = unit == 0x5f;
    final printable = unit >= 0x21 && unit <= 0x7e;
    if (!printable || underscore) {
      throw ArgumentError.value(
        info,
        'info',
        'PQXDH info is printable ASCII without spaces or underscores',
      );
    }
  }
  return Uint8List.fromList(utf8.encode('${info}_${Pqxdh.hkdfParameters}'));
}

Future<Uint8List> _dh(Uint8List secret, Uint8List remote) {
  return PqForgeHybridKeyAgreement.x25519SharedSecret(
    secretKey: secret,
    remotePublicKey: remote,
  );
}

Uint8List _ikm(
  Uint8List dh1,
  Uint8List dh2,
  Uint8List dh3,
  Uint8List? dh4,
  Uint8List ss,
) {
  final length =
      32 +
      dh1.length +
      dh2.length +
      dh3.length +
      (dh4?.length ?? 0) +
      ss.length;
  final out = Uint8List(length);
  out.fillRange(0, 32, 0xff);
  var offset = 32;
  for (final part in [dh1, dh2, dh3, ?dh4, ss]) {
    out.setRange(offset, offset + part.length, part);
    offset += part.length;
  }
  return out;
}

/// HKDF-SHA-512, salt 64 zero bytes, 32-byte OKM. RFC 5869. HMAC is pqcrypto.
Uint8List _hkdf32(Uint8List ikm, Uint8List info) {
  final salt = Uint8List(64);
  final prk = pqc.hmacSha512(salt, ikm);
  try {
    final data = Uint8List(info.length + 1);
    data.setRange(0, info.length, info);
    data[info.length] = 1;
    final block = pqc.hmacSha512(prk, data);
    secureZero(data);
    final out = Uint8List(32)..setRange(0, 32, block);
    secureZero(block);
    return out;
  } finally {
    secureZero(prk);
  }
}

Uint8List _seal(
  PqForgeCipherSuite suite,
  Uint8List key,
  Uint8List plaintext,
  Uint8List aad,
) {
  final nonce = Uint8List(12);
  return switch (suite) {
    PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmEncrypt(
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      aad: aad,
    ),
    PqForgeCipherSuite.chaCha20Poly1305 =>
      PqSymmetricPrimitives.chacha20Poly1305Encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        aad: aad,
      ),
  };
}

Uint8List _open(
  PqForgeCipherSuite suite,
  Uint8List key,
  Uint8List sealed,
  Uint8List aad,
) {
  final nonce = Uint8List(12);
  return switch (suite) {
    PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmDecrypt(
      key: key,
      nonce: nonce,
      ciphertext: sealed,
      aad: aad,
    ),
    PqForgeCipherSuite.chaCha20Poly1305 =>
      PqSymmetricPrimitives.chacha20Poly1305Decrypt(
        key: key,
        nonce: nonce,
        ciphertext: sealed,
        aad: aad,
      ),
  };
}

PqxdhMessage _encodeMessage({
  required Uint8List aliceIdentity,
  required Uint8List ephemeralKey,
  required Uint8List kemCiphertext,
  required Uint8List sealed,
  required bool oneTime,
}) {
  final bytes = Uint8List(70 + kemCiphertext.length + sealed.length);
  bytes[0] = 0x50;
  bytes[1] = 0x51;
  bytes[2] = 0x58;
  bytes[3] = 0x31;
  bytes[4] = 1;
  bytes[5] = oneTime ? 1 : 0;
  bytes.setRange(6, 38, aliceIdentity);
  bytes.setRange(38, 70, ephemeralKey);
  bytes.setRange(70, 70 + kemCiphertext.length, kemCiphertext);
  bytes.setRange(70 + kemCiphertext.length, bytes.length, sealed);
  return PqxdhMessage._(bytes);
}

void _wipeAll(List<Uint8List?> parts) {
  for (final part in parts) {
    if (part != null) secureZero(part);
  }
}
