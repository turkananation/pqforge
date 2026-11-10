/// RFC 9180 Hybrid Public Key Encryption.
///
/// Suites this library can compute:
///
/// * KEM: DHKEM(X25519, HKDF-SHA256) `0x0020`, DHKEM(X448, HKDF-SHA512)
///   `0x0021`, DHKEM(P-256, HKDF-SHA256) `0x0010`, DHKEM(P-384,
///   HKDF-SHA384) `0x0011`, DHKEM(P-521, HKDF-SHA512) `0x0012`.
/// * KDF: HKDF-SHA256 `0x0001`, HKDF-SHA384 `0x0002`, HKDF-SHA512 `0x0003`.
///   The KEM's own hash is fixed by the KEM id. The suite KDF is the key
///   schedule, and the two may differ.
/// * AEAD: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, and export-only.
/// * Modes: base, PSK, auth, and authPSK.
///
/// This is not a FIPS module and it does not change `.pqf` or `.pqfs`.
/// A sender context seals; a recipient context opens.
/// [HpkeContext.export] works on both and does not move the sequence.
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import '../cipher/pq_cipher_suite.dart';
import '../exceptions/pqforge_exception.dart';
import '../hybrid/pq_classical_provider.dart';
import '../hybrid/pq_nist_ecdh.dart';
import '../hybrid/pq_x448.dart';
import '../hybrid/pq_xwing.dart';
import '../algorithms/pq_fips.dart';
import '../primitives/pq_primitives.dart';
import 'package:zeroize/zeroize.dart';

/// RFC 9180 HPKE mode identifier.
enum HpkeMode {
  /// Base, `0x00`. No PSK and no sender authentication.
  base(0x00),

  /// PSK, `0x01`. A pre-shared key and a PSK id, no sender key.
  psk(0x01),

  /// Auth, `0x02`. The sender's KEM key authenticates the encapsulation.
  auth(0x02),

  /// AuthPSK, `0x03`. Sender key and a pre-shared key.
  authPsk(0x03);

  const HpkeMode(this.wire);

  /// The one-byte mode id mixed into the key schedule context.
  final int wire;

  /// Whether this mode requires a non-empty PSK and PSK id.
  bool get usesPsk => this == HpkeMode.psk || this == HpkeMode.authPsk;

  /// Whether this mode requires the sender's KEM key pair.
  bool get usesAuth => this == HpkeMode.auth || this == HpkeMode.authPsk;

  /// Looks up a mode by its wire byte.
  static HpkeMode fromId(int id) {
    for (final mode in values) {
      if (mode.wire == id) return mode;
    }
    throw ArgumentError.value(id, 'id', 'unsupported HPKE mode');
  }
}

/// RFC 9180 KDF identifier. [nh] is the hash output length.
enum HpkeKdf {
  /// HKDF-SHA256, `0x0001`.
  hkdfSha256(0x0001, 32),

  /// HKDF-SHA384, `0x0002`.
  hkdfSha384(0x0002, 48),

  /// HKDF-SHA512, `0x0003`.
  hkdfSha512(0x0003, 64);

  const HpkeKdf(this.id, this.nh);

  /// The two-byte KDF id.
  final int id;

  /// Hash length in bytes (`Nh`).
  final int nh;

  /// Looks up a KDF by its wire id.
  static HpkeKdf fromId(int id) {
    for (final kdf in values) {
      if (kdf.id == id) return kdf;
    }
    throw ArgumentError.value(id, 'id', 'unsupported HPKE KDF');
  }
}

/// RFC 9180 AEAD identifier.
enum HpkeAead {
  /// AES-128-GCM, `0x0001`. A 16-byte key.
  aes128Gcm(0x0001, 16, 12),

  /// AES-256-GCM, `0x0002`. A 32-byte key.
  aes256Gcm(0x0002, 32, 12),

  /// ChaCha20-Poly1305, `0x0003`. A 32-byte key.
  chacha20Poly1305(0x0003, 32, 12),

  /// Export-only, `0xFFFF`. [HpkeContext.seal] and [HpkeContext.open] fail.
  exportOnly(0xFFFF, 0, 0);

  const HpkeAead(this.id, this.nk, this.nn);

  /// The two-byte AEAD id.
  final int id;

  /// Key length in bytes (`Nk`). Zero for [exportOnly].
  final int nk;

  /// Nonce length in bytes (`Nn`). Zero for [exportOnly].
  final int nn;

  /// Whether seal and open are defined for this AEAD.
  bool get canSeal => nk != 0;

  /// Looks up an AEAD by its wire id.
  static HpkeAead fromId(int id) {
    for (final aead in values) {
      if (aead.id == id) return aead;
    }
    throw ArgumentError.value(id, 'id', 'unsupported HPKE AEAD');
  }
}

/// RFC 9180 KEM identifier.
enum HpkeKem {
  /// DHKEM(P-256, HKDF-SHA256), `0x0010`. Uncompressed SEC1 public keys.
  p256HkdfSha256(0x0010, 32, 65, 65, 32, HpkeKdf.hkdfSha256),

  /// DHKEM(P-384, HKDF-SHA384), `0x0011`. Uncompressed SEC1 public keys.
  p384HkdfSha384(0x0011, 48, 97, 97, 48, HpkeKdf.hkdfSha384),

  /// DHKEM(P-521, HKDF-SHA512), `0x0012`. Uncompressed SEC1 public keys.
  /// `Nsk` is 66. `Nsecret` is 64. The Diffie-Hellman x-coordinate is 66
  /// bytes and is not itself the HPKE shared secret.
  p521HkdfSha512(0x0012, 64, 133, 133, 66, HpkeKdf.hkdfSha512),

  /// DHKEM(X25519, HKDF-SHA256), `0x0020`.
  x25519HkdfSha256(0x0020, 32, 32, 32, 32, HpkeKdf.hkdfSha256),

  /// DHKEM(X448, HKDF-SHA512), `0x0021`. 56-byte keys. `Nsecret` is 64.
  x448HkdfSha512(0x0021, 64, 56, 56, 56, HpkeKdf.hkdfSha512),

  /// X-Wing, draft-connolly-cfrg-xwing-kem-11, requested id `0x647A`.
  /// Not a DHKEM. `Nsk` is the 32-byte seed. Auth is not defined.
  /// [kdf] is unused inside the KEM. The suite KDF is still the HPKE
  /// key schedule.
  xWing(0x647A, 32, 1120, 1216, 32, HpkeKdf.hkdfSha256);

  const HpkeKem(this.id, this.nSecret, this.nEnc, this.nPk, this.nSk, this.kdf);

  /// The two-byte KEM id.
  final int id;

  /// Shared-secret length (`Nsecret`).
  final int nSecret;

  /// Encapsulated-key length (`Nenc`).
  final int nEnc;

  /// Serialized public-key length (`Npk`).
  final int nPk;

  /// Serialized private-key length (`Nsk`).
  final int nSk;

  /// The KDF fixed by this KEM. Independent of [HpkeSuite.kdf].
  final HpkeKdf kdf;

  /// Looks up a KEM by its wire id.
  static HpkeKem fromId(int id) {
    for (final kem in values) {
      if (kem.id == id) return kem;
    }
    throw ArgumentError.value(id, 'id', 'unsupported HPKE KEM');
  }
}

/// One HPKE ciphersuite: KEM, KDF, and AEAD.
final class HpkeSuite {
  /// A suite. The default is the RFC 9180 base vector suite:
  /// X25519, HKDF-SHA256, AES-128-GCM.
  const HpkeSuite({
    this.kem = HpkeKem.x25519HkdfSha256,
    this.kdf = HpkeKdf.hkdfSha256,
    this.aead = HpkeAead.aes128Gcm,
  });

  /// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
  static const HpkeSuite x25519Aes128Gcm = HpkeSuite();

  /// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
  static const HpkeSuite x25519Aes256Gcm = HpkeSuite(aead: HpkeAead.aes256Gcm);

  /// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
  static const HpkeSuite x25519ChaCha20Poly1305 = HpkeSuite(
    aead: HpkeAead.chacha20Poly1305,
  );

  /// KEM. Its internal hash is [HpkeKem.kdf], not [kdf].
  final HpkeKem kem;

  /// Key-schedule KDF.
  final HpkeKdf kdf;

  /// AEAD, or [HpkeAead.exportOnly].
  final HpkeAead aead;
}

/// Which side of an HPKE context this is.
enum HpkeRole {
  /// May [HpkeContext.seal].
  sender,

  /// May [HpkeContext.open].
  recipient,
}

/// A KEM key pair. [secretKey] is the RFC 9180 serialized private key:
/// an X25519 or X448 seed, or a big-endian NIST scalar. The public key is
/// uncompressed SEC1 for P-256, P-384, and P-521.
final class HpkeKeyPair {
  /// Copies [secretKey] and [publicKey]. Lengths must match [kem].
  HpkeKeyPair({
    required this.kem,
    required Uint8List secretKey,
    required Uint8List publicKey,
  }) : secretKey = Uint8List.fromList(secretKey),
       publicKey = Uint8List.fromList(publicKey) {
    if (this.secretKey.length != kem.nSk) {
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'expected ${kem.nSk} bytes',
      );
    }
    if (this.publicKey.length != kem.nPk) {
      throw ArgumentError.value(
        publicKey.length,
        'publicKey',
        'expected ${kem.nPk} bytes',
      );
    }
  }

  /// KEM these bytes belong to.
  final HpkeKem kem;

  /// Serialized private key (`Nsk` bytes).
  final Uint8List secretKey;

  /// Serialized public key (`Npk` bytes).
  final Uint8List publicKey;

  @override
  String toString() => 'HpkeKeyPair(${kem.name})';
}

/// An HPKE encryption context (RFC 9180 §5.2).
///
/// [seal] and [open] are ordered. Sequence `n` on the sender matches
/// sequence `n` on the recipient. A failed [open] does not advance the
/// sequence. [export] does not use the sequence.
///
/// [dispose] is best-effort zeroization of the context secrets. It is not
/// a claim that the keys have left process memory.
final class HpkeContext {
  HpkeContext._({
    required this.suite,
    required this.role,
    required this._key,
    required this._baseNonce,
    required this._exporterSecret,
  });

  /// Suite this context was scheduled with.
  final HpkeSuite suite;

  /// Sender or recipient. The other direction's AEAD call fails.
  final HpkeRole role;

  final Uint8List _key;
  final Uint8List _baseNonce;
  final Uint8List _exporterSecret;
  var _seq = 0;
  var _disposed = false;

  /// Encrypts [plaintext]. Returns `ciphertext || tag`.
  ///
  /// Only a [HpkeRole.sender] context may call this. Export-only suites
  /// throw [PqForgeException].
  Uint8List seal(Uint8List plaintext, {Uint8List? aad}) {
    _requireLive();
    if (role != HpkeRole.sender) {
      throw const PqForgeException('HPKE recipient context cannot seal');
    }
    if (!suite.aead.canSeal) {
      throw const PqForgeException('export-only HPKE AEAD cannot seal');
    }
    final nonce = _nonce();
    final ciphertext = _aeadSeal(
      suite.aead,
      _key,
      nonce,
      plaintext,
      aad ?? Uint8List(0),
    );
    _seq++;
    return ciphertext;
  }

  /// Decrypts [ciphertext] (`ciphertext || tag`).
  ///
  /// Only a [HpkeRole.recipient] context may call this. A tag failure
  /// throws [PqForgeAuthTagException] and leaves the sequence unchanged.
  Uint8List open(Uint8List ciphertext, {Uint8List? aad}) {
    _requireLive();
    if (role != HpkeRole.recipient) {
      throw const PqForgeException('HPKE sender context cannot open');
    }
    if (!suite.aead.canSeal) {
      throw const PqForgeException('export-only HPKE AEAD cannot open');
    }
    if (ciphertext.length < 16) {
      throw const PqForgeAuthTagException(
        'HPKE ciphertext is shorter than the authentication tag',
      );
    }
    final nonce = _nonce();
    final plaintext = _aeadOpen(
      suite.aead,
      _key,
      nonce,
      ciphertext,
      aad ?? Uint8List(0),
    );
    _seq++;
    return plaintext;
  }

  /// RFC 9180 `Context.Export`. [length] is `1 .. 255 * Nh`.
  ///
  /// Does not advance the seal/open sequence. The same [exporterContext]
  /// and [length] on both peers returns the same bytes.
  Uint8List export(Uint8List exporterContext, int length) {
    _requireLive();
    final max = 255 * suite.kdf.nh;
    RangeError.checkValueInInterval(length, 1, max, 'length');
    return _labeledExpand(
      suite.kdf,
      _hpkeSuiteId(suite),
      _exporterSecret,
      'sec',
      exporterContext,
      length,
    );
  }

  /// Best-effort wipe of the key, base nonce, and exporter secret.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    secureZero(_key);
    secureZero(_baseNonce);
    secureZero(_exporterSecret);
  }

  void _requireLive() {
    if (_disposed) {
      throw const PqForgeException('HPKE context is disposed');
    }
  }

  Uint8List _nonce() {
    final n = Uint8List.fromList(_baseNonce);
    if (_seq.bitLength > n.length * 8) {
      throw const PqForgeException('HPKE sequence number exhausted');
    }
    var seq = _seq;
    for (var i = n.length - 1; i >= 0; i--) {
      n[i] ^= seq & 0xff;
      seq >>= 8;
    }
    return n;
  }
}

/// RFC 9180 HPKE setup, seal, and open.
abstract final class PqHpke {
  /// Derives a key pair from [ikm] (RFC 9180 `DeriveKeyPair`).
  ///
  /// [ikm] should be at least `Nsk` bytes of entropy for a new key. Known
  /// answers may be shorter. X25519 and X448 use
  /// `LabeledExpand(..., "sk", "", Nsk)`. P-256, P-384, and P-521 use the
  /// candidate loop against the curve order. P-521 masks the first byte
  /// with `0x01` before the integer is read.
  static Future<HpkeKeyPair> deriveKeyPair({
    required HpkeKem kem,
    required Uint8List ikm,
  }) async {
    if (kem == HpkeKem.xWing) {
      PqFipsMode.requireXWingAllowed();
      final seed = PqXWing.deriveSeed(ikm);
      ({Uint8List secretKey, Uint8List publicKey})? pair;
      try {
        pair = await PqXWing.generateKeyPairDerand(seed);
        return HpkeKeyPair(
          kem: kem,
          secretKey: pair.secretKey,
          publicKey: pair.publicKey,
        );
      } finally {
        secureZero(seed);
        if (pair != null) secureZero(pair.secretKey);
      }
    }
    final suiteId = _kemSuiteId(kem);
    final dkp = _labeledExtract(kem.kdf, suiteId, Uint8List(0), 'dkp_prk', ikm);
    try {
      final secret = switch (kem) {
        HpkeKem.x25519HkdfSha256 || HpkeKem.x448HkdfSha512 => _labeledExpand(
          kem.kdf,
          suiteId,
          dkp,
          'sk',
          Uint8List(0),
          kem.nSk,
        ),
        HpkeKem.p256HkdfSha256 ||
        HpkeKem.p384HkdfSha384 ||
        HpkeKem.p521HkdfSha512 => _deriveNistScalar(kem, suiteId, dkp),
        HpkeKem.xWing => throw StateError(
          'X-Wing DeriveKeyPair does not use labeled expand',
        ),
      };
      try {
        final publicKey = await _publicKey(kem, secret);
        return HpkeKeyPair(kem: kem, secretKey: secret, publicKey: publicKey);
      } finally {
        secureZero(secret);
      }
    } finally {
      secureZero(dkp);
    }
  }

  /// Generates a fresh key pair for [kem].
  static Future<HpkeKeyPair> generateKeyPair(HpkeKem kem) async {
    switch (kem) {
      case HpkeKem.x25519HkdfSha256:
        final pair = await PqClassical.provider.x25519GenerateKeyPair();
        try {
          return HpkeKeyPair(
            kem: kem,
            secretKey: pair.secretKey,
            publicKey: pair.publicKey,
          );
        } finally {
          secureZero(pair.secretKey);
        }
      case HpkeKem.p256HkdfSha256:
        final pair = PqNistEcdh.p256GenerateKeyPair();
        try {
          return HpkeKeyPair(
            kem: kem,
            secretKey: pair.secretKey,
            publicKey: pair.publicKey,
          );
        } finally {
          secureZero(pair.secretKey);
        }
      case HpkeKem.x448HkdfSha512:
        final pair = PqX448.generateKeyPair();
        try {
          return HpkeKeyPair(
            kem: kem,
            secretKey: pair.secretKey,
            publicKey: pair.publicKey,
          );
        } finally {
          secureZero(pair.secretKey);
        }
      case HpkeKem.p521HkdfSha512:
        final pair = PqNistEcdh.p521GenerateKeyPair();
        try {
          return HpkeKeyPair(
            kem: kem,
            secretKey: pair.secretKey,
            publicKey: pair.publicKey,
          );
        } finally {
          secureZero(pair.secretKey);
        }
      case HpkeKem.p384HkdfSha384:
        final pair = PqNistEcdh.p384GenerateKeyPair();
        try {
          return HpkeKeyPair(
            kem: kem,
            secretKey: pair.secretKey,
            publicKey: pair.publicKey,
          );
        } finally {
          secureZero(pair.secretKey);
        }
      case HpkeKem.xWing:
        PqFipsMode.requireXWingAllowed();
        final pair = await PqXWing.generateKeyPair();
        try {
          return HpkeKeyPair(
            kem: kem,
            secretKey: pair.secretKey,
            publicKey: pair.publicKey,
          );
        } finally {
          secureZero(pair.secretKey);
        }
    }
  }

  /// `Setup<mode>S`. Returns the encapsulated key and a sender context.
  ///
  /// For a DHKEM, [ephemeralIkm] is the RFC 9180 `DeriveKeyPair` ikm. It
  /// is not the BoringSSL X25519 testing seed (that seed is the ephemeral
  /// private key). For [HpkeKem.xWing] it is the 64-byte encapsulation
  /// seed, and a 32-byte value is rejected. Omit it outside tests.
  static Future<({Uint8List enc, HpkeContext context})> setupSender({
    required HpkeSuite suite,
    required HpkeMode mode,
    required Uint8List recipientPublicKey,
    Uint8List? info,
    Uint8List? psk,
    Uint8List? pskId,
    HpkeKeyPair? senderKey,
    Uint8List? ephemeralIkm,
  }) async {
    if (suite.kem == HpkeKem.xWing) {
      PqFipsMode.requireXWingAllowed();
      if (mode.usesAuth) {
        throw ArgumentError('X-Wing is not an authenticated KEM');
      }
    }
    final materials = _materials(
      suite: suite,
      mode: mode,
      recipientPublicKey: recipientPublicKey,
      info: info,
      psk: psk,
      pskId: pskId,
      senderKey: senderKey,
    );
    final encapsulated = await _encap(
      kem: suite.kem,
      recipientPublicKey: materials.recipientPublicKey,
      senderKey: materials.senderKey,
      ephemeralIkm: ephemeralIkm,
    );
    final context = _schedule(
      suite: suite,
      mode: mode,
      role: HpkeRole.sender,
      sharedSecret: encapsulated.sharedSecret,
      info: materials.info,
      psk: materials.psk,
      pskId: materials.pskId,
    );
    return (enc: encapsulated.enc, context: context);
  }

  /// `Setup<mode>R`. [enc] is the encapsulated key from [setupSender].
  ///
  /// Auth modes require [senderPublicKey], the sender's serialized KEM
  /// public key.
  static Future<HpkeContext> setupRecipient({
    required HpkeSuite suite,
    required HpkeMode mode,
    required Uint8List enc,
    required HpkeKeyPair recipientKey,
    Uint8List? info,
    Uint8List? psk,
    Uint8List? pskId,
    Uint8List? senderPublicKey,
  }) async {
    if (suite.kem == HpkeKem.xWing) {
      PqFipsMode.requireXWingAllowed();
      if (mode.usesAuth) {
        throw ArgumentError('X-Wing is not an authenticated KEM');
      }
    }
    if (recipientKey.kem != suite.kem) {
      throw ArgumentError.value(
        recipientKey.kem,
        'recipientKey.kem',
        'does not match ${suite.kem.name}',
      );
    }
    final materials = _materials(
      suite: suite,
      mode: mode,
      recipientPublicKey: recipientKey.publicKey,
      info: info,
      psk: psk,
      pskId: pskId,
      senderPublicKey: senderPublicKey,
    );
    if (enc.length != suite.kem.nEnc) {
      throw ArgumentError.value(
        enc.length,
        'enc',
        'expected ${suite.kem.nEnc} bytes',
      );
    }
    final shared = await _decap(
      recipientKey: recipientKey,
      enc: enc,
      senderPublicKey: materials.senderPublicKey,
    );
    return _schedule(
      suite: suite,
      mode: mode,
      role: HpkeRole.recipient,
      sharedSecret: shared,
      info: materials.info,
      psk: materials.psk,
      pskId: materials.pskId,
    );
  }

  /// Seals one message. The returned context has already consumed sequence 0,
  /// so a later [HpkeContext.seal] continues at sequence 1. [HpkeContext.export]
  /// is unaffected.
  static Future<({Uint8List enc, Uint8List ciphertext, HpkeContext context})>
  seal({
    required HpkeSuite suite,
    required HpkeMode mode,
    required Uint8List recipientPublicKey,
    required Uint8List plaintext,
    Uint8List? info,
    Uint8List? aad,
    Uint8List? psk,
    Uint8List? pskId,
    HpkeKeyPair? senderKey,
    Uint8List? ephemeralIkm,
  }) async {
    final setup = await setupSender(
      suite: suite,
      mode: mode,
      recipientPublicKey: recipientPublicKey,
      info: info,
      psk: psk,
      pskId: pskId,
      senderKey: senderKey,
      ephemeralIkm: ephemeralIkm,
    );
    final ciphertext = setup.context.seal(plaintext, aad: aad);
    return (enc: setup.enc, ciphertext: ciphertext, context: setup.context);
  }

  /// Opens one message produced by [seal]. The returned context has consumed
  /// sequence 0.
  static Future<({Uint8List plaintext, HpkeContext context})> open({
    required HpkeSuite suite,
    required HpkeMode mode,
    required Uint8List enc,
    required Uint8List ciphertext,
    required HpkeKeyPair recipientKey,
    Uint8List? info,
    Uint8List? aad,
    Uint8List? psk,
    Uint8List? pskId,
    Uint8List? senderPublicKey,
  }) async {
    final context = await setupRecipient(
      suite: suite,
      mode: mode,
      enc: enc,
      recipientKey: recipientKey,
      info: info,
      psk: psk,
      pskId: pskId,
      senderPublicKey: senderPublicKey,
    );
    final plaintext = context.open(ciphertext, aad: aad);
    return (plaintext: plaintext, context: context);
  }
}

final class _Materials {
  _Materials({
    required this.recipientPublicKey,
    required this.info,
    required this.psk,
    required this.pskId,
    required this.senderKey,
    required this.senderPublicKey,
  });

  final Uint8List recipientPublicKey;
  final Uint8List info;
  final Uint8List psk;
  final Uint8List pskId;
  final HpkeKeyPair? senderKey;
  final Uint8List? senderPublicKey;
}

_Materials _materials({
  required HpkeSuite suite,
  required HpkeMode mode,
  required Uint8List recipientPublicKey,
  Uint8List? info,
  Uint8List? psk,
  Uint8List? pskId,
  HpkeKeyPair? senderKey,
  Uint8List? senderPublicKey,
}) {
  if (recipientPublicKey.length != suite.kem.nPk) {
    throw ArgumentError.value(
      recipientPublicKey.length,
      'recipientPublicKey',
      'expected ${suite.kem.nPk} bytes',
    );
  }
  final pskBytes = Uint8List.fromList(psk ?? Uint8List(0));
  final pskIdBytes = Uint8List.fromList(pskId ?? Uint8List(0));
  final pskEmpty = pskBytes.isEmpty && pskIdBytes.isEmpty;
  final pskFull = pskBytes.isNotEmpty && pskIdBytes.isNotEmpty;
  if (mode.usesPsk && !pskFull) {
    throw ArgumentError('HPKE PSK modes require a non-empty psk and pskId');
  }
  if (!mode.usesPsk && !pskEmpty) {
    throw ArgumentError('HPKE base and auth modes reject a PSK');
  }
  if (!pskEmpty && !pskFull) {
    throw ArgumentError('HPKE psk and pskId must both be set or both be empty');
  }
  if (mode.usesAuth) {
    if (senderKey != null) {
      if (senderKey.kem != suite.kem) {
        throw ArgumentError.value(
          senderKey.kem,
          'senderKey.kem',
          'does not match ${suite.kem.name}',
        );
      }
    } else if (senderPublicKey == null) {
      throw ArgumentError('HPKE auth modes require the sender KEM key');
    }
    if (senderPublicKey != null && senderPublicKey.length != suite.kem.nPk) {
      throw ArgumentError.value(
        senderPublicKey.length,
        'senderPublicKey',
        'expected ${suite.kem.nPk} bytes',
      );
    }
  } else if (senderKey != null || senderPublicKey != null) {
    throw ArgumentError('HPKE base and PSK modes reject a sender key');
  }
  return _Materials(
    recipientPublicKey: Uint8List.fromList(recipientPublicKey),
    info: Uint8List.fromList(info ?? Uint8List(0)),
    psk: pskBytes,
    pskId: pskIdBytes,
    senderKey: senderKey,
    senderPublicKey: senderPublicKey == null
        ? null
        : Uint8List.fromList(senderPublicKey),
  );
}

Future<({Uint8List enc, Uint8List sharedSecret})> _encap({
  required HpkeKem kem,
  required Uint8List recipientPublicKey,
  required HpkeKeyPair? senderKey,
  required Uint8List? ephemeralIkm,
}) async {
  if (kem == HpkeKem.xWing) {
    if (senderKey != null) {
      throw ArgumentError('X-Wing is not an authenticated KEM');
    }
    if (ephemeralIkm != null && ephemeralIkm.length != PqXWing.eseedBytes) {
      throw ArgumentError(
        'X-Wing ephemeralIkm must be the 64-byte encapsulation seed',
      );
    }
    final encapsulated = ephemeralIkm == null
        ? await PqXWing.encapsulate(recipientPublicKey)
        : await PqXWing.encapsulateDerand(recipientPublicKey, ephemeralIkm);
    return (
      enc: encapsulated.ciphertext,
      sharedSecret: encapsulated.sharedSecret,
    );
  }
  final ephemeral = ephemeralIkm == null
      ? await PqHpke.generateKeyPair(kem)
      : await PqHpke.deriveKeyPair(kem: kem, ikm: ephemeralIkm);
  try {
    final dhEphemeral = await _dh(kem, ephemeral.secretKey, recipientPublicKey);
    Uint8List? dhAuth;
    if (senderKey != null) {
      await _requireMatchingPublicKey(kem, senderKey);
      dhAuth = await _dh(kem, senderKey.secretKey, recipientPublicKey);
    }
    try {
      final dh = dhAuth == null
          ? dhEphemeral
          : PqBytes.concat([dhEphemeral, dhAuth]);
      final kemContext = senderKey == null
          ? PqBytes.concat([ephemeral.publicKey, recipientPublicKey])
          : PqBytes.concat([
              ephemeral.publicKey,
              recipientPublicKey,
              senderKey.publicKey,
            ]);
      final shared = _extractAndExpand(kem, dh, kemContext);
      if (dhAuth != null) secureZero(dh);
      return (
        enc: Uint8List.fromList(ephemeral.publicKey),
        sharedSecret: shared,
      );
    } finally {
      secureZero(dhEphemeral);
      if (dhAuth != null) secureZero(dhAuth);
    }
  } finally {
    secureZero(ephemeral.secretKey);
  }
}

Future<Uint8List> _decap({
  required HpkeKeyPair recipientKey,
  required Uint8List enc,
  required Uint8List? senderPublicKey,
}) async {
  if (recipientKey.kem == HpkeKem.xWing) {
    if (senderPublicKey != null) {
      throw ArgumentError('X-Wing is not an authenticated KEM');
    }
    await _requireMatchingPublicKey(recipientKey.kem, recipientKey);
    return PqXWing.decapsulate(enc, recipientKey.secretKey);
  }
  await _requireMatchingPublicKey(recipientKey.kem, recipientKey);
  final dhEphemeral = await _dh(recipientKey.kem, recipientKey.secretKey, enc);
  Uint8List? dhAuth;
  if (senderPublicKey != null) {
    dhAuth = await _dh(
      recipientKey.kem,
      recipientKey.secretKey,
      senderPublicKey,
    );
  }
  try {
    final dh = dhAuth == null
        ? dhEphemeral
        : PqBytes.concat([dhEphemeral, dhAuth]);
    final kemContext = senderPublicKey == null
        ? PqBytes.concat([enc, recipientKey.publicKey])
        : PqBytes.concat([enc, recipientKey.publicKey, senderPublicKey]);
    final shared = _extractAndExpand(recipientKey.kem, dh, kemContext);
    if (dhAuth != null) secureZero(dh);
    return shared;
  } finally {
    secureZero(dhEphemeral);
    if (dhAuth != null) secureZero(dhAuth);
  }
}

Future<void> _requireMatchingPublicKey(HpkeKem kem, HpkeKeyPair key) async {
  final derived = await _publicKey(kem, key.secretKey);
  if (!PqBytes.constantTimeEquals(derived, key.publicKey)) {
    throw ArgumentError('HPKE public key does not match the private key');
  }
}

Future<Uint8List> _publicKey(HpkeKem kem, Uint8List secretKey) async {
  switch (kem) {
    case HpkeKem.x25519HkdfSha256:
      final pair = await PqClassical.provider.x25519GenerateKeyPair(
        seed: secretKey,
      );
      secureZero(pair.secretKey);
      return pair.publicKey;
    case HpkeKem.p256HkdfSha256:
      return PqNistEcdh.p256PublicKeyFromPrivate(secretKey);
    case HpkeKem.p384HkdfSha384:
      return PqNistEcdh.p384PublicKeyFromPrivate(secretKey);
    case HpkeKem.p521HkdfSha512:
      return PqNistEcdh.p521PublicKeyFromPrivate(secretKey);
    case HpkeKem.x448HkdfSha512:
      return PqX448.publicKeyFromPrivate(secretKey);
    case HpkeKem.xWing:
      final pair = await PqXWing.generateKeyPairDerand(secretKey);
      secureZero(pair.secretKey);
      return pair.publicKey;
  }
}

Future<Uint8List> _dh(
  HpkeKem kem,
  Uint8List secretKey,
  Uint8List remotePublicKey,
) async {
  switch (kem) {
    case HpkeKem.x25519HkdfSha256:
      final shared = await PqClassical.provider.x25519SharedSecret(
        secretKey: secretKey,
        remotePublicKey: remotePublicKey,
      );
      if (_isAllZero(shared)) {
        secureZero(shared);
        throw const PqForgeException('X25519 shared secret is all zeros');
      }
      return shared;
    case HpkeKem.p256HkdfSha256:
      return PqNistEcdh.p256SharedSecret(
        secretKey: secretKey,
        remotePublicKey: remotePublicKey,
      );
    case HpkeKem.p384HkdfSha384:
      return PqNistEcdh.p384SharedSecret(
        secretKey: secretKey,
        remotePublicKey: remotePublicKey,
      );
    case HpkeKem.p521HkdfSha512:
      return PqNistEcdh.p521SharedSecret(
        secretKey: secretKey,
        remotePublicKey: remotePublicKey,
      );
    case HpkeKem.x448HkdfSha512:
      final shared = PqX448.sharedSecret(
        secretKey: secretKey,
        remotePublicKey: remotePublicKey,
      );
      if (_isAllZero(shared)) {
        secureZero(shared);
        throw const PqForgeException('X448 shared secret is all zeros');
      }
      return shared;
    case HpkeKem.xWing:
      throw StateError('X-Wing is not a DHKEM');
  }
}

HpkeContext _schedule({
  required HpkeSuite suite,
  required HpkeMode mode,
  required HpkeRole role,
  required Uint8List sharedSecret,
  required Uint8List info,
  required Uint8List psk,
  required Uint8List pskId,
}) {
  final suiteId = _hpkeSuiteId(suite);
  Uint8List? pskIdHash;
  Uint8List? infoHash;
  Uint8List? scheduleContext;
  Uint8List? secret;
  try {
    pskIdHash = _labeledExtract(
      suite.kdf,
      suiteId,
      Uint8List(0),
      'psk_id_hash',
      pskId,
    );
    infoHash = _labeledExtract(
      suite.kdf,
      suiteId,
      Uint8List(0),
      'info_hash',
      info,
    );
    scheduleContext = PqBytes.concat([
      Uint8List.fromList([mode.wire]),
      pskIdHash,
      infoHash,
    ]);
    // Salt is the KEM shared secret. IKM is the PSK. Swapping them will
    // not match a known answer.
    secret = _labeledExtract(suite.kdf, suiteId, sharedSecret, 'secret', psk);
    final key = _labeledExpand(
      suite.kdf,
      suiteId,
      secret,
      'key',
      scheduleContext,
      suite.aead.nk,
    );
    final baseNonce = _labeledExpand(
      suite.kdf,
      suiteId,
      secret,
      'base_nonce',
      scheduleContext,
      suite.aead.nn,
    );
    final exporterSecret = _labeledExpand(
      suite.kdf,
      suiteId,
      secret,
      'exp',
      scheduleContext,
      suite.kdf.nh,
    );
    return HpkeContext._(
      suite: suite,
      role: role,
      key: key,
      baseNonce: baseNonce,
      exporterSecret: exporterSecret,
    );
  } finally {
    if (pskIdHash != null) secureZero(pskIdHash);
    if (infoHash != null) secureZero(infoHash);
    if (scheduleContext != null) secureZero(scheduleContext);
    if (secret != null) secureZero(secret);
    secureZero(sharedSecret);
  }
}

Uint8List _extractAndExpand(HpkeKem kem, Uint8List dh, Uint8List kemContext) {
  final suiteId = _kemSuiteId(kem);
  final prk = _labeledExtract(kem.kdf, suiteId, Uint8List(0), 'eae_prk', dh);
  try {
    return _labeledExpand(
      kem.kdf,
      suiteId,
      prk,
      'shared_secret',
      kemContext,
      kem.nSecret,
    );
  } finally {
    secureZero(prk);
  }
}

Uint8List _deriveNistScalar(HpkeKem kem, Uint8List suiteId, Uint8List dkpPrk) {
  final order = _nistDomain(kem).n;
  // RFC 9180 §7.1.4. P-256 and P-384 are a multiple of 8 bits, so the
  // mask is 0xFF. P-521 is 521 bits, so the top 7 bits of the first byte
  // are cleared.
  final bitmask = kem == HpkeKem.p521HkdfSha512 ? 0x01 : 0xff;
  for (var counter = 0; counter <= 255; counter++) {
    final candidate = _labeledExpand(
      kem.kdf,
      suiteId,
      dkpPrk,
      'candidate',
      Uint8List.fromList([counter]),
      kem.nSk,
    );
    candidate[0] &= bitmask;
    final scalar = _os2ip(candidate);
    secureZero(candidate);
    if (scalar != BigInt.zero && scalar < order) {
      return _i2osp(scalar, kem.nSk);
    }
  }
  throw const PqForgeException('HPKE DeriveKeyPair failed for a NIST KEM');
}

pc.ECDomainParameters _nistDomain(HpkeKem kem) => switch (kem) {
  HpkeKem.p256HkdfSha256 => _p256,
  HpkeKem.p384HkdfSha384 => _p384,
  HpkeKem.p521HkdfSha512 => _p521,
  HpkeKem.x25519HkdfSha256 ||
  HpkeKem.x448HkdfSha512 ||
  HpkeKem.xWing => throw StateError('${kem.name} is not a NIST KEM'),
};

final _p256 = pc.ECCurve_secp256r1();
final _p384 = pc.ECCurve_secp384r1();
final _p521 = pc.ECCurve_secp521r1();

final Uint8List _hpkeVersion = Uint8List.fromList('HPKE-v1'.codeUnits);

Uint8List _kemSuiteId(HpkeKem kem) {
  final out = Uint8List(5);
  out.setRange(0, 3, 'KEM'.codeUnits);
  _put16(out, 3, kem.id);
  return out;
}

Uint8List _hpkeSuiteId(HpkeSuite suite) {
  final out = Uint8List(10);
  out.setRange(0, 4, 'HPKE'.codeUnits);
  _put16(out, 4, suite.kem.id);
  _put16(out, 6, suite.kdf.id);
  _put16(out, 8, suite.aead.id);
  return out;
}

void _put16(Uint8List out, int offset, int value) {
  out[offset] = (value >> 8) & 0xff;
  out[offset + 1] = value & 0xff;
}

Uint8List _labeledExtract(
  HpkeKdf kdf,
  Uint8List suiteId,
  Uint8List salt,
  String label,
  Uint8List ikm,
) {
  final labeled = PqBytes.concat([
    _hpkeVersion,
    suiteId,
    Uint8List.fromList(label.codeUnits),
    ikm,
  ]);
  final usedSalt = salt.isEmpty ? Uint8List(kdf.nh) : salt;
  return _hmac(kdf, usedSalt, labeled);
}

Uint8List _labeledExpand(
  HpkeKdf kdf,
  Uint8List suiteId,
  Uint8List prk,
  String label,
  Uint8List info,
  int length,
) {
  if (length == 0) return Uint8List(0);
  final labeled = PqBytes.concat([
    Uint8List(2)
      ..[0] = (length >> 8) & 0xff
      ..[1] = length & 0xff,
    _hpkeVersion,
    suiteId,
    Uint8List.fromList(label.codeUnits),
    info,
  ]);
  return _hkdfExpand(kdf, prk, labeled, length);
}

Uint8List _hmac(HpkeKdf kdf, Uint8List key, Uint8List data) => switch (kdf) {
  HpkeKdf.hkdfSha256 => PqBytes.hmacSha256(key: key, data: data),
  HpkeKdf.hkdfSha384 => PqBytes.hmacSha384(key: key, data: data),
  HpkeKdf.hkdfSha512 => PqBytes.hmacSha512(key: key, data: data),
};

Uint8List _hkdfExpand(
  HpkeKdf kdf,
  Uint8List prk,
  Uint8List info,
  int outputBytes,
) {
  final hashLen = kdf.nh;
  RangeError.checkValueInInterval(outputBytes, 1, 255 * hashLen, 'outputBytes');
  final n = (outputBytes + hashLen - 1) ~/ hashLen;
  final okm = Uint8List(n * hashLen);
  var previous = Uint8List(0);
  var offset = 0;
  for (var i = 1; i <= n; i++) {
    final block = _hmac(
      kdf,
      prk,
      PqBytes.concat([
        previous,
        info,
        Uint8List.fromList([i]),
      ]),
    );
    okm.setRange(offset, offset + hashLen, block);
    offset += hashLen;
    previous = block;
  }
  return Uint8List.sublistView(okm, 0, outputBytes);
}

BigInt _os2ip(Uint8List bytes) {
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

Uint8List _i2osp(BigInt value, int length) {
  final out = Uint8List(length);
  var rest = value;
  final mask = BigInt.from(0xff);
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (rest & mask).toInt();
    rest >>= 8;
  }
  if (rest != BigInt.zero) {
    throw ArgumentError('HPKE integer does not fit in $length bytes');
  }
  return out;
}

bool _isAllZero(Uint8List bytes) {
  var acc = 0;
  for (final byte in bytes) {
    acc |= byte;
  }
  return acc == 0;
}

void _requireFipsAead(HpkeAead aead) {
  if (!PqFipsMode.isEnabled || aead == HpkeAead.aes256Gcm) return;
  throw PqForgeException(
    'FIPS mode forbids the HPKE AEAD ${aead.name}; use aes-256-gcm',
  );
}

Uint8List _aeadSeal(
  HpkeAead aead,
  Uint8List key,
  Uint8List nonce,
  Uint8List plaintext,
  Uint8List aad,
) {
  _requireFipsAead(aead);
  switch (aead) {
    case HpkeAead.aes128Gcm:
      return PqSymmetricPrimitives.aes128GcmEncrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        aad: aad,
      );
    case HpkeAead.aes256Gcm:
      return PqSymmetricPrimitives.aesGcmEncrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        aad: aad,
      );
    case HpkeAead.chacha20Poly1305:
      return PqSymmetricPrimitives.chacha20Poly1305Encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        aad: aad,
      );
    case HpkeAead.exportOnly:
      throw const PqForgeException('export-only HPKE AEAD cannot seal');
  }
}

Uint8List _aeadOpen(
  HpkeAead aead,
  Uint8List key,
  Uint8List nonce,
  Uint8List ciphertext,
  Uint8List aad,
) {
  _requireFipsAead(aead);
  try {
    return switch (aead) {
      HpkeAead.aes128Gcm => PqSymmetricPrimitives.aes128GcmDecrypt(
        key: key,
        nonce: nonce,
        ciphertext: ciphertext,
        aad: aad,
      ),
      HpkeAead.aes256Gcm => PqSymmetricPrimitives.aesGcmDecrypt(
        key: key,
        nonce: nonce,
        ciphertext: ciphertext,
        aad: aad,
      ),
      HpkeAead.chacha20Poly1305 =>
        PqSymmetricPrimitives.chacha20Poly1305Decrypt(
          key: key,
          nonce: nonce,
          ciphertext: ciphertext,
          aad: aad,
        ),
      HpkeAead.exportOnly => throw const PqForgeException(
        'export-only HPKE AEAD cannot open',
      ),
    };
  } on PqForgeAuthTagException {
    rethrow;
  } on PqForgeException {
    rethrow;
  } on ArgumentError {
    rethrow;
  } catch (_) {
    throw const PqForgeAuthTagException('HPKE authentication failed');
  }
}
