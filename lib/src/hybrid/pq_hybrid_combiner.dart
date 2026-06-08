/// Hybrid (classical + post-quantum) shared-secret combiner for pqforge.
///
/// This is the **Option A** core: a zero-dependency surface that relies
/// exclusively on `package:pointycastle`. It ingests the raw classical and
/// post-quantum shared-secret bytes that a caller obtained from their own
/// classical KEX (for example X25519 / ECDHE) and their ML-KEM encapsulation,
/// and folds them into a single symmetric session key with HKDF.
///
/// The construction is the "concatenate-then-KDF" hybrid combiner described by
/// the emerging IETF specifications — notably
/// `draft-ietf-tls-hybrid-design` and `draft-kwiatkowski-tls-ecdhe-mlkem`:
///
/// ```text
/// concatenatedSecret = classicalSharedSecret || postQuantumSharedSecret
/// sessionKey         = HKDF(ikm: concatenatedSecret, salt, info, L)
/// ```
///
/// The classical bytes strictly precede the post-quantum bytes and no length
/// prefixes or separators are inserted: per those drafts the length of each
/// share is fixed by the negotiated ciphersuite, so framing would be redundant
/// and would diverge from the on-the-wire transcript that peers must agree on.
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import '../algorithms/pq_algorithms.dart';

/// Hash digest engine + security-profile pairing used by [PqForgeCombiner].
///
/// Fixing the digest fixes the HKDF extract/expand boundary so the combiner
/// stays inside the cryptographic strength of the negotiated KEM. The mapping
/// is intentionally closed (only vetted SHA-2 members) so a caller can never
/// downgrade the KDF to a weak or non-collision-resistant hash.
enum PqHybridProfile {
  /// Balanced profile — SHA-256 HKDF. Pairs with ML-KEM-768 (NIST level 3).
  balanced('SHA-256', 32),

  /// Heavy / high-security profile — SHA-512 HKDF. Pairs with ML-KEM-1024
  /// (NIST level 5).
  heavy('SHA-512', 64);

  const PqHybridProfile(this.digestName, this.digestSizeBytes);

  /// Human-readable digest identifier, for diagnostics and logging only.
  final String digestName;

  /// Output size of the underlying digest in bytes (HKDF `HashLen`).
  ///
  /// HKDF can expand at most `255 * HashLen` bytes, so this also bounds the
  /// largest key [PqForgeCombiner.combine] will produce for the profile.
  final int digestSizeBytes;

  /// Builds a fresh PointyCastle [pc.Digest] for this profile.
  ///
  /// A new instance is returned on every call so the HKDF derivator never
  /// shares mutable digest state across derivations.
  pc.Digest createDigest() => switch (this) {
    PqHybridProfile.balanced => pc.SHA256Digest(),
    PqHybridProfile.heavy => pc.SHA512Digest(),
  };
}

/// Core hybrid KEM shared-secret combiner (Option A — pure byte ingestion).
///
/// [PqForgeCombiner] is stateless and `const`-constructible; a single instance
/// is safe to reuse across derivations. Each [combine] call allocates its own
/// intermediate buffers and wipes them before returning.
///
/// ```dart
/// final combiner = PqForgeCombiner.balanced();
/// final sessionKey = combiner.combine(
///   classicalSharedSecret: x25519Shared, // e.g. 32 bytes
///   postQuantumSharedSecret: mlKemShared, // 32 bytes for ML-KEM
///   info: utf8.encode('myapp/tls13-hybrid/v1') as Uint8List,
/// );
/// ```
class PqForgeCombiner {
  /// Creates a combiner bound to [profile] (defaults to [PqHybridProfile.balanced]).
  const PqForgeCombiner({this.profile = PqHybridProfile.balanced});

  /// Balanced profile combiner (SHA-256 HKDF, ML-KEM-768 class).
  const PqForgeCombiner.balanced() : profile = PqHybridProfile.balanced;

  /// Heavy / high-security profile combiner (SHA-512 HKDF, ML-KEM-1024 class).
  const PqForgeCombiner.heavy() : profile = PqHybridProfile.heavy;

  /// The digest profile that powers HKDF extraction and expansion.
  final PqHybridProfile profile;

  /// Default derived-key length in bytes (a 256-bit AEAD session key).
  static const int defaultLength = pqForgeDefaultSessionKeyBytes;

  /// Combines a classical and a post-quantum shared secret into one session key.
  ///
  /// The inputs are concatenated as `classicalSharedSecret ||
  /// postQuantumSharedSecret` (classical first, no framing) and run through
  /// HKDF using this combiner's [profile] digest.
  ///
  /// Parameters:
  /// * [classicalSharedSecret] — raw bytes from the classical KEX. Because no
  ///   length framing is used, this MUST have the fixed length defined by the
  ///   ciphersuite; mixing variable lengths is a misuse.
  /// * [postQuantumSharedSecret] — raw bytes from the ML-KEM decapsulation
  ///   (32 bytes for every ML-KEM parameter set).
  /// * [info] — mandatory domain-separation label (HKDF `info`). Encode the
  ///   protocol, version, and role here (e.g. `myapp/handshake/v1/client`) to
  ///   prevent cross-protocol context collisions. Must be non-empty.
  /// * [salt] — optional HKDF salt. When `null` or empty, RFC 5869's default
  ///   salt of `HashLen` zero bytes is used. A transcript hash or a
  ///   per-deployment value is a good choice here.
  /// * [length] — output key length in bytes (1 .. `255 * HashLen`). Defaults
  ///   to [defaultLength] (32).
  ///
  /// Throws [ArgumentError] for an empty secret or empty [info], and
  /// [RangeError] for an out-of-range [length].
  ///
  /// Memory hygiene: the concatenated input keying material is overwritten with
  /// zeros immediately after derivation (in a `finally`), so the joined secret
  /// never outlives the call. Callers remain responsible for wiping the input
  /// secrets they own — see [wipe].
  Uint8List combine({
    required Uint8List classicalSharedSecret,
    required Uint8List postQuantumSharedSecret,
    required Uint8List info,
    Uint8List? salt,
    int length = defaultLength,
  }) {
    if (classicalSharedSecret.isEmpty) {
      throw ArgumentError.value(
        classicalSharedSecret.length,
        'classicalSharedSecret',
        'must not be empty',
      );
    }
    if (postQuantumSharedSecret.isEmpty) {
      throw ArgumentError.value(
        postQuantumSharedSecret.length,
        'postQuantumSharedSecret',
        'must not be empty',
      );
    }
    if (info.isEmpty) {
      throw ArgumentError.value(
        info.length,
        'info',
        'domain-separation info must not be empty',
      );
    }
    RangeError.checkValueInInterval(
      length,
      1,
      255 * profile.digestSizeBytes,
      'length',
    );

    // IETF hybrid ordering: classical bytes strictly precede post-quantum
    // bytes, with no length prefixes or separators.
    final classicalLength = classicalSharedSecret.length;
    final concatenatedSecret =
        Uint8List(classicalLength + postQuantumSharedSecret.length)
          ..setRange(0, classicalLength, classicalSharedSecret)
          ..setRange(
            classicalLength,
            classicalLength + postQuantumSharedSecret.length,
            postQuantumSharedSecret,
          );

    try {
      final derivator = pc.HKDFKeyDerivator(profile.createDigest())
        ..init(pc.HkdfParameters(concatenatedSecret, length, salt, info));
      final sessionKey = Uint8List(length);
      // `inp` must be null: a non-null value would be appended to `info`.
      derivator.deriveKey(null, 0, sessionKey, 0);
      return sessionKey;
    } finally {
      // Overwrite the joined secret regardless of success or thrown error.
      wipe(concatenatedSecret);
    }
  }

  /// Overwrites [buffer] in place with zero bytes.
  ///
  /// Exposed as the library's zeroization primitive: use it to scrub raw
  /// shared-secret buffers once they are no longer needed. Dart cannot
  /// guarantee the runtime keeps no other copy, but eagerly zeroing shortens
  /// the window in which key material is resident.
  static void wipe(Uint8List buffer) {
    buffer.fillRange(0, buffer.length, 0);
  }
}
