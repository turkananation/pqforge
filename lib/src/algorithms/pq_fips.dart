/// FIPS deployment policy (FIPS 140-3 oriented) for pqforge.
///
/// pqforge's algorithm set can be deployed in a FIPS-oriented way — ML-KEM
/// (FIPS 203), ML-DSA / HashML-DSA (FIPS 204), SLH-DSA / HashSLH-DSA (FIPS 205),
/// AES-256-GCM (SP 800-38D), SHA-256 (FIPS 180-4), HKDF (SP 800-56C rev 2) —
/// but several defaults are deliberately outside that set:
/// ChaCha20-Poly1305, Argon2id, X-Wing, RSA-SHA-1, and a modulus under
/// 2048 bits. [PqFipsMode] lets a deployment refuse those at runtime.
///
/// Enabling the mode enforces, at the package's sanctioned entry points:
///
///  * AEAD suite must be AES-256-GCM (`PqForgeSecureSession`,
///    `PqForgeStreamCipher`, `PqHpke` seal and open);
///  * passphrase key wrapping must use PBKDF2-HMAC-SHA256 (SP 800-132), not
///    Argon2id;
///  * X-Wing is rejected by `PqHpke` and `PqForgeHybridKeyAgreement`
///    (`PqXWing` itself does not read the flag, so its known answers still run);
///  * `PqRsa.signPkcs1` / `signPss` reject SHA-1 and a modulus under 2048 bits.
///    The verify methods return false for those inputs instead of throwing.
///
/// The flag is per isolate. `encryptFileInBackground` and
/// `decryptFileInBackground` turn it back on in the worker. A custom
/// `PqRandom.generator` cannot cross that boundary and those helpers throw
/// instead of falling back to the platform CSPRNG.
///
/// `PqForgeSecureSession` nonces are a random 32-bit salt plus a 64-bit
/// counter (SP 800-38D §8.2.1). They are not a purely random 96-bit IV.
/// The mode does not gate Brainpool, FFDHE, AES-128-GCM at the primitive
/// (QUIC Initial still needs it), a raw `PqForgeAeadEngine.seal`, or
/// `PqXWing` itself. It also does not make this package a validated
/// module. For actual FIPS 140-3 compliance, route the AEAD through a
/// validated module and the lattice ops through `PqLatticeProvider`, and
/// source randomness from the module via `PqRandom.generator`. See
/// `doc/security/CLAIM_BOUNDARY.md`.
library;

import 'package:pqforge/src/exceptions/pqforge_exception.dart';

import '../cipher/pq_cipher_suite.dart';

/// KDF identifiers stored in wrapped-key JSON (`PqWrappedKey.kdf`).
abstract final class PqKdf {
  /// Argon2id — the stronger password KDF; **not** FIPS-approved.
  static const argon2id = 'argon2id';

  /// PBKDF2-HMAC-SHA256 (NIST SP 800-132) — the FIPS-approved password KDF.
  static const pbkdf2HmacSha256 = 'pbkdf2-hmac-sha256';
}

/// Process-wide FIPS policy switch. Enable once at startup, before any crypto.
abstract final class PqFipsMode {
  static bool _enabled = false;

  /// Whether FIPS restrictions are active.
  static bool get isEnabled => _enabled;

  /// Activates the policy. Irreversible by design in production flows; tests
  /// may call [disable].
  static void enable() => _enabled = true;

  /// Deactivates the policy (intended for tests).
  static void disable() => _enabled = false;

  /// Throws unless [suite] is FIPS-approved (AES-256-GCM) when the mode is on.
  static void requireApprovedSuite(PqForgeCipherSuite suite) {
    if (_enabled && suite != PqForgeCipherSuite.aes256Gcm) {
      throw PqForgeException(
        'FIPS mode forbids the ${suite.id} cipher suite; use aes-256-gcm',
      );
    }
  }

  /// Throws unless [kdf] is FIPS-approved (PBKDF2-HMAC-SHA256) when the mode
  /// is on.
  static void requireApprovedKdf(String kdf) {
    if (_enabled && kdf != PqKdf.pbkdf2HmacSha256) {
      throw PqForgeException(
        'FIPS mode forbids the $kdf KDF; use ${PqKdf.pbkdf2HmacSha256}',
      );
    }
  }

  /// X-Wing is not a FIPS construction. [PqXWing] itself does not call this,
  /// so its known-answer tests still run while the flag is on.
  static void requireXWingAllowed() {
    if (_enabled) {
      throw const PqForgeException('FIPS mode forbids X-Wing');
    }
  }
}
