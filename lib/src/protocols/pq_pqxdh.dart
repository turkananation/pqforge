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
/// * KEM: ML-KEM through `pqcrypto`, default ML-KEM-1024. The spec's example
///   string names CRYSTALS-Kyber-1024. These bytes are ML-KEM, so the HKDF
///   info names the parameter set. Round-3 Kyber is not implemented.
/// * `EncodeKEM` is the raw encapsulation key. ML-KEM-1024 is 1568 bytes.
///   ML-KEM-768 is 1184. ML-KEM-512 is 800. Version 1 of `PQX1` is the
///   1568-byte ciphertext only. A different KEM is version 2, and both
///   sides pass that KEM. It is not read off the wire. The ranges are
///   disjoint from `EncodeEC` by length. ML-KEM does not bind that key
///   into the ciphertext, so it is appended to the AEAD associated data.
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
import '../keys/pq_keys.dart';
import '../primitives/pq_primitives.dart';
import 'pq_double_ratchet.dart';
import 'pq_pqxdh_kem.dart';
import 'pq_ratchet_types.dart';

/// The KEM this profile runs. Not X-Wing, and not round-3 Kyber.
///
/// [kyber1024] is the name this package already shipped for ML-KEM-1024.
/// Version 1 messages are that KEM only. [mlKem512] and [mlKem768] require
/// a version 2 message (`signedPrekeyId` set). The caller on each side
/// passes the same value. The wire does not negotiate it.
enum PqxdhKem {
  /// ML-KEM-512. Public key 800, ciphertext 768, secret 1632.
  mlKem512(publicKeyBytes: 800, ciphertextBytes: 768, secretKeyBytes: 1632),

  /// ML-KEM-768. Public key 1184, ciphertext 1088, secret 2400.
  mlKem768(publicKeyBytes: 1184, ciphertextBytes: 1088, secretKeyBytes: 2400),

  /// ML-KEM-1024. Public key 1568, ciphertext 1568, secret 3168.
  kyber1024(publicKeyBytes: 1568, ciphertextBytes: 1568, secretKeyBytes: 3168);

  const PqxdhKem({
    required this.publicKeyBytes,
    required this.ciphertextBytes,
    required this.secretKeyBytes,
  });

  final int publicKeyBytes;
  final int ciphertextBytes;
  final int secretKeyBytes;

  /// The [PqKemAlgorithm] this profile runs.
  PqKemAlgorithm get algorithm => switch (this) {
    PqxdhKem.mlKem512 => PqKemAlgorithm.mlKem512,
    PqxdhKem.mlKem768 => PqKemAlgorithm.mlKem768,
    PqxdhKem.kyber1024 => PqKemAlgorithm.mlKem1024,
  };

  /// Where FIPS 203 stores the encapsulation key inside the secret key.
  int get encapsulationKeyOffset => secretKeyBytes - 64 - publicKeyBytes;

  /// HKDF info suffix. The 1024 string is the historical constant.
  String get hkdfParameters => switch (this) {
    PqxdhKem.kyber1024 => Pqxdh.hkdfParameters,
    PqxdhKem.mlKem768 => 'CURVE25519_SHA-512_ML-KEM-768',
    PqxdhKem.mlKem512 => 'CURVE25519_SHA-512_ML-KEM-512',
  };
}

/// Who signed a prekey bundle. Lattice or hash-based. Not an input to SK.
///
/// One signature, once, over [Pqxdh.bundleSigningBytes]. It is not attached
/// to later messages. An `s` set is a valid choice. It is slow. An `f` set
/// is the fast hash-based choice.
final class PqxdhTrust {
  /// ML-DSA-44, ML-DSA-65, or ML-DSA-87.
  const PqxdhTrust.mlDsa(this.mlDsa) : slhDsa = null;

  /// One of the twelve SLH-DSA parameter sets.
  const PqxdhTrust.slhDsa(this.slhDsa) : mlDsa = null;

  /// ML-DSA-44.
  static const mlDsa44 = PqxdhTrust.mlDsa(PqSignatureAlgorithm.mlDsa44);

  /// ML-DSA-65. The conversation default.
  static const mlDsa65 = PqxdhTrust.mlDsa(PqSignatureAlgorithm.mlDsa65);

  /// ML-DSA-87.
  static const mlDsa87 = PqxdhTrust.mlDsa(PqSignatureAlgorithm.mlDsa87);

  /// SLH-DSA-SHAKE-128f. The fast hash-based identity.
  static const shake128f = PqxdhTrust.slhDsa(PqSlhDsaAlgorithm.shake128f);

  /// SLH-DSA-SHAKE-192f. Matches [PqForgeProfile.balanced].
  static const shake192f = PqxdhTrust.slhDsa(PqSlhDsaAlgorithm.shake192f);

  /// SLH-DSA-SHAKE-256f. Matches [PqForgeProfile.maximum]. Larger and slower.
  static const shake256f = PqxdhTrust.slhDsa(PqSlhDsaAlgorithm.shake256f);

  /// Set when this identity is ML-DSA.
  final PqSignatureAlgorithm? mlDsa;

  /// Set when this identity is SLH-DSA.
  final PqSlhDsaAlgorithm? slhDsa;

  /// `ml-dsa-65`, `slh-dsa-shake-128f`, and the other ids.
  String get id => mlDsa?.id ?? slhDsa!.id;

  /// Public key length.
  int get publicKeyBytes => mlDsa?.publicKeyBytes ?? slhDsa!.publicKeyBytes;

  /// Signature length.
  int get signatureBytes => mlDsa?.signatureBytes ?? slhDsa!.signatureBytes;

  /// Secret key length.
  int get secretKeyBytes => mlDsa?.secretKeyBytes ?? slhDsa!.secretKeyBytes;

  /// True for an SLH-DSA `s` set.
  bool get isSlow => slhDsa != null && !slhDsa!.isFast;

  @override
  bool operator ==(Object other) =>
      other is PqxdhTrust && other.mlDsa == mlDsa && other.slhDsa == slhDsa;

  @override
  int get hashCode => Object.hash(mlDsa, slhDsa);
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
    this.signedPrekeyId,
    this.oneTimePrekeyId,
    this.trust,
    Uint8List? trustPublicKey,
    Uint8List? trustSignature,
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
       kemPublicKey = _kemKey(kem, kemPublicKey),
       trustPublicKey = _trustPublic(trust, trustPublicKey),
       trustSignature = _trustSignature(trust, trustPublicKey, trustSignature) {
    _requireId('signedPrekeyId', signedPrekeyId);
    _requireId('oneTimePrekeyId', oneTimePrekeyId);
    if (oneTimePrekeyId != null && signedPrekeyId == null) {
      throw ArgumentError('oneTimePrekeyId requires signedPrekeyId');
    }
    if (oneTimePrekeyId != null && oneTimePrekey == null) {
      throw ArgumentError('oneTimePrekeyId requires a one-time prekey');
    }
    if (signedPrekeyId != null &&
        oneTimePrekey != null &&
        oneTimePrekeyId == null) {
      throw ArgumentError('version 2 one-time prekey needs an id');
    }
  }

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

  /// Encapsulation key for [kem].
  final Uint8List kemPublicKey;

  final PqxdhKem kem;

  /// Present on a version 2 bundle. Absent means the version 1 message.
  final int? signedPrekeyId;

  /// Present only beside a one-time prekey on a version 2 bundle.
  final int? oneTimePrekeyId;

  /// Lattice or hash-based identity that signs [Pqxdh.bundleSigningBytes].
  /// Not the X25519 identity. Null when the publisher did not attach one.
  final PqxdhTrust? trust;

  /// Public key for [trust].
  final Uint8List? trustPublicKey;

  /// Signature over [Pqxdh.bundleSigningBytes].
  final Uint8List? trustSignature;

  /// Version 2 initial message. Version 1 stays the historical layout.
  bool get identifiesPrekeys => signedPrekeyId != null;
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

/// Alice's first message. Version 1 is the original layout. Version 2
/// adds the prekey ids. The AEAD is still under SK.
///
/// ```text
/// "PQX1" || version || flags || IK_A(32) || EK_A(32)
///        || [signedPrekeyId(u32) || oneTimePrekeyId(u32)]  // version 2
///        || CT || AEAD
/// ```
///
/// Version 1 `CT` is 1568 bytes (ML-KEM-1024). Version 2 `CT` is the
/// ciphertext length of the KEM both sides passed. `flags` bit 0 means a
/// one-time curve prekey was used. The AEAD nonce is not on the wire. It
/// is 12 zero bytes. A version 2 id of 0 is only legal for the one-time
/// slot when that flag is clear.
final class PqxdhMessage {
  PqxdhMessage._(this.bytes, this.kem);

  /// Parses [bytes]. The fields are views.
  ///
  /// [kem] is the KEM the caller agreed. Version 1 accepts only
  /// [PqxdhKem.kyber1024]. The split between ciphertext and AEAD is that
  /// length. A different guess does not open.
  factory PqxdhMessage.parse(
    Uint8List bytes, {
    PqxdhKem kem = PqxdhKem.kyber1024,
  }) {
    if (bytes.length < 6 ||
        bytes[0] != 0x50 ||
        bytes[1] != 0x51 ||
        bytes[2] != 0x58 ||
        bytes[3] != 0x31) {
      throw const PqForgeException('Not a PQXDH initial message');
    }
    final version = bytes[4];
    if (version != 1 && version != 2) {
      throw const PqForgeException('Unknown PQXDH message version');
    }
    if (version == 1 && kem != PqxdhKem.kyber1024) {
      throw const PqForgeException('PQXDH version 1 is ML-KEM-1024');
    }
    if (bytes[5] > 1) {
      throw const PqForgeException('Unknown PQXDH message flags');
    }
    final start = version == 1 ? 70 : 78;
    if (bytes.length < start + kem.ciphertextBytes + 16) {
      throw const PqForgeException('PQXDH initial message is truncated');
    }
    if (version == 2 && bytes[5] == 0) {
      final opk = ByteData.sublistView(bytes, 74, 78).getUint32(0);
      if (opk != 0) {
        throw const PqForgeException(
          'PQXDH one-time prekey id does not match the flag',
        );
      }
    }
    if (version == 2 && bytes[5] == 1) {
      final opk = ByteData.sublistView(bytes, 74, 78).getUint32(0);
      if (opk == 0) {
        throw const PqForgeException('PQXDH one-time prekey id is missing');
      }
    }
    return PqxdhMessage._(bytes, kem);
  }

  /// Owned by [Pqxdh.initiate]. Viewed by [parse].
  final Uint8List bytes;

  /// KEM that splits [kemCiphertext] from [sealed].
  final PqxdhKem kem;

  /// 1 or 2.
  int get version => bytes[4];

  int get _kemStart => version == 1 ? 70 : 78;

  /// Alice's identity public key. A view.
  Uint8List get aliceIdentity => Uint8List.sublistView(bytes, 6, 38);

  /// Alice's handshake ephemeral public key. A view. Not her ratchet key.
  Uint8List get ephemeralKey => Uint8List.sublistView(bytes, 38, 70);

  /// ML-KEM ciphertext. A view. The length is [PqxdhKem.ciphertextBytes].
  Uint8List get kemCiphertext =>
      Uint8List.sublistView(bytes, _kemStart, _kemStart + kem.ciphertextBytes);

  /// `ciphertext || tag` under SK. A view.
  Uint8List get sealed =>
      Uint8List.sublistView(bytes, _kemStart + kem.ciphertextBytes);

  /// Whether Alice used Bob's one-time curve prekey.
  bool get usedOneTimePrekey => bytes[5] == 1;

  /// Version 2 signed-prekey id. Null on version 1.
  int? get signedPrekeyId =>
      version == 1 ? null : ByteData.sublistView(bytes, 70, 74).getUint32(0);

  /// Version 2 one-time prekey id. Null on version 1. Zero when unused.
  int? get oneTimePrekeyId =>
      version == 1 ? null : ByteData.sublistView(bytes, 74, 78).getUint32(0);
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

  /// Whether [bundle]'s ML-DSA-65 identity signed [bundleSigningBytes].
  ///
  /// False for any other trust algorithm, and when the bundle has no
  /// identity. [trustAuthentic] is the check for every algorithm.
  /// XEdDSA is a separate check. This is not mixed into SK.
  static bool mlDsaAuthentic(PqxdhBundle bundle) {
    if (bundle.trust != PqxdhTrust.mlDsa65) return false;
    final publicKey = bundle.trustPublicKey;
    final signature = bundle.trustSignature;
    if (publicKey == null || signature == null) return false;
    return PqSignaturePrimitives.verify(
      PqSignatureAlgorithm.mlDsa65,
      publicKey,
      bundleSigningBytes(bundle),
      signature,
    );
  }

  /// Whether [bundle.trust] signed [bundleSigningBytes].
  ///
  /// False when the bundle has no trust identity. The result is not an
  /// input to SK. [offload] runs SLH-DSA, and pure-Dart ML-DSA, on a
  /// worker when the runtime has one.
  static Future<bool> trustAuthentic(
    PqxdhBundle bundle, {
    bool offload = true,
  }) {
    final trust = bundle.trust;
    final publicKey = bundle.trustPublicKey;
    final signature = bundle.trustSignature;
    if (trust == null || publicKey == null || signature == null) {
      return Future.value(false);
    }
    return pqxdhTrustVerify(
      publicKey,
      bundleSigningBytes(bundle),
      signature,
      mlDsa: trust.mlDsa,
      slhDsa: trust.slhDsa,
      offload: offload,
    );
  }

  /// Canonical bundle bytes. Domain, both curve prekeys, their ids, and
  /// the ML-KEM encapsulation key. Not the XEdDSA signatures.
  ///
  /// When [bundle] carries a trust identity, the algorithm id is appended
  /// on its own line. The public key is not in this message. The caller
  /// pins that key separately.
  static Uint8List bundleSigningBytes(PqxdhBundle bundle) {
    final domain = utf8.encode('pqforge/pqxdh-bundle/v1\n');
    final opk = bundle.oneTimePrekey?.bytes ?? Uint8List(32);
    final algorithm = bundle.trust == null
        ? Uint8List(0)
        : utf8.encode('\n${bundle.trust!.id}');
    final out = Uint8List(
      domain.length +
          32 +
          32 +
          4 +
          bundle.kemPublicKey.length +
          32 +
          4 +
          algorithm.length,
    );
    var offset = 0;
    out.setRange(0, domain.length, domain);
    offset = domain.length;
    out.setRange(offset, offset + 32, bundle.identityKey.bytes);
    offset += 32;
    out.setRange(offset, offset + 32, bundle.signedPrekey.bytes);
    offset += 32;
    ByteData.sublistView(out).setUint32(offset, bundle.signedPrekeyId ?? 0);
    offset += 4;
    out.setRange(
      offset,
      offset + bundle.kemPublicKey.length,
      bundle.kemPublicKey,
    );
    offset += bundle.kemPublicKey.length;
    out.setRange(offset, offset + 32, opk);
    offset += 32;
    ByteData.sublistView(out).setUint32(offset, bundle.oneTimePrekeyId ?? 0);
    offset += 4;
    out.setRange(offset, offset + algorithm.length, algorithm);
    return out;
  }

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
    if (kemPublicKey.length != 800 &&
        kemPublicKey.length != 1184 &&
        kemPublicKey.length != 1568) {
      throw ArgumentError.value(
        kemPublicKey.length,
        'kemPublicKey',
        'expected an ML-KEM-512, ML-KEM-768, or ML-KEM-1024 public key',
      );
    }
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
    int? signedPrekeyId,
    int? oneTimePrekeyId,
    PqKeyPair? trustKey,
    PqxdhTrust trust = PqxdhTrust.mlDsa65,
    bool offload = true,
  }) async {
    if (kem != PqxdhKem.kyber1024 && signedPrekeyId == null) {
      throw ArgumentError(
        'PQXDH version 1 is ML-KEM-1024. Pass signedPrekeyId.',
      );
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
      kem.algorithm,
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
      final unsigned = PqxdhBundle(
        identityKey: identity.publicKey,
        signedPrekey: signedPrekey.publicKey,
        signedPrekeySignature: spkSignature,
        kemPublicKeySignature: kemSignature,
        oneTimePrekey: oneTime?.publicKey,
        kemPublicKey: kemPublic,
        kem: kem,
        signedPrekeyId: signedPrekeyId,
        oneTimePrekeyId: oneTimePrekeyId,
        trust: trustKey == null ? null : trust,
        trustPublicKey: trustKey?.publicKey,
      );
      final bundle = trustKey == null
          ? unsigned
          : await _signBundle(unsigned, trustKey, offload: offload);
      return PqxdhPrekeys(
        identityKey: identity,
        signedPrekey: signedPrekey,
        oneTimePrekey: oneTime,
        kemSecretKey: kemSecret,
        bundle: bundle,
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
    bool offload = true,
  }) async {
    PqFipsMode.requireApprovedSuite(suite);
    if (kem != bundle.kem) {
      throw ArgumentError.value(kem, 'kem', 'does not match the bundle');
    }
    if (kem != PqxdhKem.kyber1024 && !bundle.identifiesPrekeys) {
      throw ArgumentError(
        'PQXDH version 1 is ML-KEM-1024. The bundle needs signedPrekeyId.',
      );
    }
    if (identityKey.publicKey.bytes.length != RatchetPublicKey.length) {
      throw ArgumentError.value(
        identityKey.publicKey.bytes.length,
        'identityKey',
        'expected 32 bytes',
      );
    }
    final infoBytes = _hkdfInfo(info, kem);
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
        algorithm: kem.algorithm,
        offload: offload,
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
        kem: kem,
        signedPrekeyId: bundle.signedPrekeyId,
        oneTimePrekeyId: bundle.oneTimePrekeyId,
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
    bool offload = true,
  }) async {
    PqFipsMode.requireApprovedSuite(suite);
    if (kem != PqxdhKem.kyber1024 && initialMessage.version == 1) {
      throw const PqForgeException('PQXDH version 1 is ML-KEM-1024');
    }
    if (initialMessage.kem != kem) {
      throw ArgumentError.value(kem, 'kem', 'does not match the message');
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
    final infoBytes = _hkdfInfo(info, kem);
    final kemPublic = Uint8List.sublistView(
      kemSecretKey,
      kem.encapsulationKeyOffset,
      kem.encapsulationKeyOffset + kem.publicKeyBytes,
    );
    Uint8List? dh1, dh2, dh3, dh4, ss, ikm, sk;
    try {
      ss = await pqxdhKemDecapsulate(
        kemSecretKey,
        initialMessage.kemCiphertext,
        algorithm: kem.algorithm,
        offload: offload,
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

Uint8List _hkdfInfo(String info, PqxdhKem kem) {
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
  return Uint8List.fromList(utf8.encode('${info}_${kem.hkdfParameters}'));
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
  required PqxdhKem kem,
  int? signedPrekeyId,
  int? oneTimePrekeyId,
}) {
  final version2 = signedPrekeyId != null;
  final header = version2 ? 78 : 70;
  final bytes = Uint8List(header + kemCiphertext.length + sealed.length);
  bytes[0] = 0x50;
  bytes[1] = 0x51;
  bytes[2] = 0x58;
  bytes[3] = 0x31;
  bytes[4] = version2 ? 2 : 1;
  bytes[5] = oneTime ? 1 : 0;
  bytes.setRange(6, 38, aliceIdentity);
  bytes.setRange(38, 70, ephemeralKey);
  if (version2) {
    ByteData.sublistView(bytes).setUint32(70, signedPrekeyId);
    ByteData.sublistView(bytes).setUint32(74, oneTime ? oneTimePrekeyId! : 0);
  }
  bytes.setRange(header, header + kemCiphertext.length, kemCiphertext);
  bytes.setRange(header + kemCiphertext.length, bytes.length, sealed);
  return PqxdhMessage._(bytes, kem);
}

Future<PqxdhBundle> _signBundle(
  PqxdhBundle unsigned,
  PqKeyPair identity, {
  required bool offload,
}) async {
  final trust = unsigned.trust;
  if (trust == null || unsigned.signedPrekeyId == null) {
    throw ArgumentError('A trust identity requires signedPrekeyId');
  }
  requireLength('trustSecretKey', identity.secretKey, trust.secretKeyBytes);
  requireLength('trustPublicKey', identity.publicKey, trust.publicKeyBytes);
  final signature = await pqxdhTrustSign(
    identity.secretKey,
    Pqxdh.bundleSigningBytes(unsigned),
    mlDsa: trust.mlDsa,
    slhDsa: trust.slhDsa,
    offload: offload,
  );
  return PqxdhBundle(
    identityKey: unsigned.identityKey,
    signedPrekey: unsigned.signedPrekey,
    signedPrekeySignature: unsigned.signedPrekeySignature,
    kemPublicKeySignature: unsigned.kemPublicKeySignature,
    oneTimePrekey: unsigned.oneTimePrekey,
    kemPublicKey: unsigned.kemPublicKey,
    kem: unsigned.kem,
    signedPrekeyId: unsigned.signedPrekeyId,
    oneTimePrekeyId: unsigned.oneTimePrekeyId,
    trust: trust,
    trustPublicKey: identity.publicKey,
    trustSignature: signature,
  );
}

Uint8List? _trustPublic(PqxdhTrust? trust, Uint8List? publicKey) {
  if (trust == null && publicKey == null) return null;
  if (trust == null || publicKey == null) {
    throw ArgumentError('Trust algorithm and public key are a pair');
  }
  requireLength('trustPublicKey', publicKey, trust.publicKeyBytes);
  return Uint8List.fromList(publicKey);
}

Uint8List? _trustSignature(
  PqxdhTrust? trust,
  Uint8List? publicKey,
  Uint8List? signature,
) {
  if (signature == null) return null;
  if (trust == null || publicKey == null) {
    throw ArgumentError('Trust signature requires an algorithm and a key');
  }
  requireLength('trustSignature', signature, trust.signatureBytes);
  return Uint8List.fromList(signature);
}

void _requireId(String name, int? id) {
  if (id == null) return;
  if (id < 0 || id > 0xFFFFFFFF) {
    throw ArgumentError.value(id, name, 'uint32');
  }
}

void _wipeAll(List<Uint8List?> parts) {
  for (final part in parts) {
    if (part != null) secureZero(part);
  }
}
