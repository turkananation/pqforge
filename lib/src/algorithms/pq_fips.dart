/// FIPS deployment policy (FIPS 140-3 oriented) for pqforge.
///
/// pqforge's algorithm set is FIPS-approved end to end — ML-KEM (FIPS 203),
/// ML-DSA / HashML-DSA (FIPS 204), AES-256-GCM with deterministic IVs
/// (SP 800-38D), SHA-256 (FIPS 180-4), HKDF (SP 800-56C rev 2) — but two
/// defaults are deliberately *better-than-FIPS* and therefore not approved:
/// ChaCha20-Poly1305 as an alternative AEAD suite, and Argon2id as the
/// passphrase KDF. [PqFipsMode] lets a deployment refuse those at runtime.
///
/// Enabling the mode enforces, at the package's sanctioned entry points:
///
///  * AEAD suite must be AES-256-GCM (`PqForgeSecureSession`,
///    `PqForgeStreamCipher`);
///  * passphrase key wrapping must use PBKDF2-HMAC-SHA256 (SP 800-132), not
///    Argon2id.
///
/// What a runtime flag **cannot** do is make the implementation a validated
/// cryptographic module. For actual FIPS 140-3 compliance, route the AEAD
/// through `PqForgeAeadEngine` to an OS validated module and the lattice ops
/// through `PqLatticeProvider` to a validated library, and source randomness
/// from the module via `PqRandom.generator`. See
/// `doc/technical/SCOPE_AUDIT_AND_LIMITS.md` §5.
library;

import '../cipher/pq_cipher_suite.dart';
import 'pq_algorithms.dart';

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
}
