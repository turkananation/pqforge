/// X-Wing, draft-connolly-cfrg-xwing-kem-11.
///
/// One ML-KEM-768 encapsulation and one X25519, combined by
/// `SHA3-256(ss_M || ss_X || ct_X || pk_X || 5c2e2f2f5e5c)`.
/// The secret is the 32-byte seed. The expanded ML-KEM private key is
/// not returned. This is not the pqforge hybrid, not PQXDH, and not a
/// `.pqf` / `.pqfs` algorithm. FIPS mode is enforced by [PqHpke] and
/// [PqForgeHybridKeyAgreement], not by this type, so the known-answer
/// tests can run while the flag is on.
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:pqcrypto/pqcrypto.dart' hide secureZero;
import 'package:zeroize/zeroize.dart';

import '../algorithms/pq_algorithms.dart';
import '../exceptions/pqforge_exception.dart';
import '../primitives/pq_primitives.dart';
import 'pq_classical_provider.dart';

/// X-Wing key encapsulation.
abstract final class PqXWing {
  /// Seed and decapsulation-key length.
  static const seedBytes = 32;

  /// Encapsulation-key length. ML-KEM-768 public key, then X25519.
  static const publicKeyBytes = 1216;

  /// Ciphertext length. ML-KEM-768 ciphertext, then the X25519 ephemeral.
  static const ciphertextBytes = 1120;

  /// Shared-secret length.
  static const sharedSecretBytes = 32;

  /// Derandomized encapsulation seed. ML-KEM coins, then the X25519 scalar.
  static const eseedBytes = 64;

  static const _mlKemPublicBytes = 1184;
  static const _mlKemCiphertextBytes = 1088;

  /// ASCII `\./` + `/^\`. Last input to the combiner, not first.
  static final Uint8List _label = Uint8List.fromList(const [
    0x5c,
    0x2e,
    0x2f,
    0x2f,
    0x5e,
    0x5c,
  ]);

  /// `SHAKE256(ikm, 32)`. HPKE `DeriveKeyPair` uses this. A 32-byte [ikm]
  /// is still hashed. [generateKeyPair] does not.
  static Uint8List deriveSeed(Uint8List ikm) => _shake256(ikm, seedBytes);

  /// Fresh 32-byte seed. Not shaken.
  static Future<({Uint8List secretKey, Uint8List publicKey})>
  generateKeyPair() async {
    final seed = PqBytes.randomBytes(seedBytes);
    try {
      return await generateKeyPairDerand(seed);
    } finally {
      secureZero(seed);
    }
  }

  /// `GenerateKeyPairDerand`. [seed] is the secret.
  static Future<({Uint8List secretKey, Uint8List publicKey})>
  generateKeyPairDerand(Uint8List seed) async {
    requireLength('seed', seed, seedBytes);
    final expanded = await _expand(seed);
    try {
      return (
        secretKey: Uint8List.fromList(seed),
        publicKey: PqBytes.concat([expanded.pkM, expanded.pkX]),
      );
    } finally {
      _wipeExpanded(expanded);
    }
  }

  /// Encapsulation with a fresh 64-byte seed.
  static Future<({Uint8List ciphertext, Uint8List sharedSecret})> encapsulate(
    Uint8List publicKey,
  ) async {
    final eseed = PqBytes.randomBytes(eseedBytes);
    try {
      return await encapsulateDerand(publicKey, eseed);
    } finally {
      secureZero(eseed);
    }
  }

  /// `EncapsulateDerand`. [eseed] is 64 bytes: ML-KEM coins, then the
  /// X25519 ephemeral scalar.
  static Future<({Uint8List ciphertext, Uint8List sharedSecret})>
  encapsulateDerand(Uint8List publicKey, Uint8List eseed) async {
    requireLength('publicKey', publicKey, publicKeyBytes);
    requireLength('eseed', eseed, eseedBytes);
    final pkM = Uint8List.sublistView(publicKey, 0, _mlKemPublicBytes);
    final pkX = Uint8List.fromList(
      Uint8List.sublistView(publicKey, _mlKemPublicBytes),
    );
    final coins = Uint8List.sublistView(eseed, 0, seedBytes);
    final ekX = Uint8List.fromList(Uint8List.sublistView(eseed, seedBytes));
    Uint8List? ctX;
    Uint8List? ssX;
    Uint8List? ssM;
    Uint8List? ctM;
    Uint8List? preimage;
    try {
      final ephemeral = await PqClassical.provider.x25519GenerateKeyPair(
        seed: ekX,
      );
      secureZero(ephemeral.secretKey);
      ctX = ephemeral.publicKey;
      ssX = await PqClassical.provider.x25519SharedSecret(
        secretKey: ekX,
        remotePublicKey: pkX,
      );
      try {
        final encapsulated = PqcKem.kyber768.encapsulate(
          Uint8List.fromList(pkM),
          Uint8List.fromList(coins),
        );
        ctM = encapsulated.$1;
        ssM = encapsulated.$2;
      } on ArgumentError {
        throw const PqForgeException('ML-KEM encapsulation key check failed');
      }
      final combined = _combine(ssM: ssM, ssX: ssX, ctX: ctX, pkX: pkX);
      preimage = combined.preimage;
      return (
        ciphertext: PqBytes.concat([ctM, ctX]),
        sharedSecret: combined.sharedSecret,
      );
    } finally {
      secureZero(pkX);
      secureZero(ekX);
      if (ctX != null) secureZero(ctX);
      if (ssX != null) secureZero(ssX);
      if (ssM != null) secureZero(ssM);
      if (ctM != null) secureZero(ctM);
      if (preimage != null) secureZero(preimage);
    }
  }

  /// `Decapsulate`. [secretKey] is the 32-byte seed. The X25519 public
  /// key mixed into the combiner is recomputed from that seed.
  static Future<Uint8List> decapsulate(
    Uint8List ciphertext,
    Uint8List secretKey,
  ) async {
    requireLength('ciphertext', ciphertext, ciphertextBytes);
    requireLength('secretKey', secretKey, seedBytes);
    final expanded = await _expand(secretKey);
    Uint8List? ssM;
    Uint8List? ssX;
    Uint8List? preimage;
    try {
      final ctM = Uint8List.sublistView(ciphertext, 0, _mlKemCiphertextBytes);
      final ctX = Uint8List.sublistView(ciphertext, _mlKemCiphertextBytes);
      ssM = PqcKem.kyber768.decapsulate(expanded.skM, Uint8List.fromList(ctM));
      ssX = await PqClassical.provider.x25519SharedSecret(
        secretKey: expanded.skX,
        remotePublicKey: ctX,
      );
      final combined = _combine(
        ssM: ssM,
        ssX: ssX,
        ctX: ctX,
        pkX: expanded.pkX,
      );
      preimage = combined.preimage;
      return combined.sharedSecret;
    } finally {
      _wipeExpanded(expanded);
      if (ssM != null) secureZero(ssM);
      if (ssX != null) secureZero(ssX);
      if (preimage != null) secureZero(preimage);
    }
  }

  static Future<({Uint8List pkM, Uint8List skM, Uint8List pkX, Uint8List skX})>
  _expand(Uint8List seed) async {
    final expanded = _shake256(seed, 96);
    final dz = Uint8List.sublistView(expanded, 0, 64);
    final skX = Uint8List.fromList(Uint8List.sublistView(expanded, 64));
    try {
      final pair = PqcKem.kyber768.generateKeyPair(Uint8List.fromList(dz));
      final x = await PqClassical.provider.x25519GenerateKeyPair(seed: skX);
      secureZero(x.secretKey);
      return (pkM: pair.$1, skM: pair.$2, pkX: x.publicKey, skX: skX);
    } finally {
      secureZero(expanded);
    }
  }

  static void _wipeExpanded(
    ({Uint8List pkM, Uint8List skM, Uint8List pkX, Uint8List skX}) expanded,
  ) {
    secureZero(expanded.pkM);
    secureZero(expanded.skM);
    secureZero(expanded.pkX);
    secureZero(expanded.skX);
  }

  static ({Uint8List sharedSecret, Uint8List preimage}) _combine({
    required Uint8List ssM,
    required Uint8List ssX,
    required Uint8List ctX,
    required Uint8List pkX,
  }) {
    final preimage = PqBytes.concat([ssM, ssX, ctX, pkX, _label]);
    return (sharedSecret: _sha3256(preimage), preimage: preimage);
  }
}

Uint8List _shake256(Uint8List input, int outLen) {
  final digest = pc.SHAKEDigest(256);
  digest.update(input, 0, input.length);
  final out = Uint8List(outLen);
  digest.doFinalRange(out, 0, outLen);
  return out;
}

Uint8List _sha3256(Uint8List input) => pc.SHA3Digest(256).process(input);
