/// Cipher-suite, engine-provider, and AEAD-engine contracts for pqforge's
/// secure session layer.
///
/// These types are pure Dart — no PointyCastle or `package:cryptography`
/// imports — so they are dependency-free and shared by every backend
/// implementation.
library;

import 'dart:typed_data';

/// Authenticated Encryption with Associated Data (AEAD) suites offered by
/// [PqForgeSecureSession].
///
/// Both suites use a 256-bit key, a 96-bit (12-byte) nonce, and a 128-bit
/// (16-byte) authentication tag. That shared geometry is what lets a wire
/// packet produced by one backend be decrypted by the other.
enum PqForgeCipherSuite {
  /// AES-256-GCM — the enterprise standard; fastest where AES-NI hardware
  /// acceleration is available.
  aes256Gcm(id: 'aes-256-gcm', keyLength: 32, nonceLength: 12, tagLength: 16),

  /// ChaCha20-Poly1305 (RFC 8439) — constant-time in software and ideal on
  /// platforms without dedicated AES instructions (many mobile CPUs).
  chaCha20Poly1305(
    id: 'chacha20-poly1305',
    keyLength: 32,
    nonceLength: 12,
    tagLength: 16,
  );

  const PqForgeCipherSuite({
    required this.id,
    required this.keyLength,
    required this.nonceLength,
    required this.tagLength,
  });

  /// Stable lowercase identifier (useful for headers, logs, or negotiation).
  final String id;

  /// Required symmetric key length in bytes.
  final int keyLength;

  /// Nonce / IV length in bytes — also the wire-packet prefix length.
  final int nonceLength;

  /// Authentication tag length in bytes (appended to the ciphertext).
  final int tagLength;

  /// Throws [ArgumentError] unless [key] is exactly [keyLength] bytes.
  void requireKey(Uint8List key) {
    if (key.length != keyLength) {
      throw ArgumentError.value(
        key.length,
        'key',
        '$name requires a $keyLength-byte key',
      );
    }
  }

  /// Throws [ArgumentError] unless [nonce] is exactly [nonceLength] bytes.
  void requireNonce(Uint8List nonce) {
    if (nonce.length != nonceLength) {
      throw ArgumentError.value(
        nonce.length,
        'nonce',
        '$name requires a $nonceLength-byte nonce',
      );
    }
  }
}

/// The backend that performs the low-level AEAD computation.
enum PqForgeEngineProvider {
  /// Pure Dart via PointyCastle — zero native dependencies.
  pureDart,

  /// `package:cryptography` — may use hardware-accelerated OS bindings.
  nativeCryptography,
}

/// Thrown when AEAD authentication-tag verification fails during decryption.
///
/// This is a distinct, immutable cryptographic exception (rather than a generic
/// backend error) so callers can react to integrity failures explicitly without
/// inspecting backend-specific error types or messages. Every backend funnels
/// its tag failure into this single type, which also avoids leaking a
/// distinguishable error shape that could feed a padding/oracle attack.
class PqForgeAuthTagException implements Exception {
  const PqForgeAuthTagException(this.message);

  final String message;

  @override
  String toString() => 'PqForgeAuthTagException: $message';
}

/// Low-level AEAD contract: raw seal/open over a `ciphertext || tag` body.
///
/// Implementations are responsible only for the cryptography and for funnelling
/// tag failures into [PqForgeAuthTagException]. Nonce generation and the
/// `nonce || body` wire framing are owned by [PqForgeSecureSession], so engines
/// stay small and backend-swappable.
abstract interface class PqForgeAeadEngine {
  /// The cipher suite this engine implements.
  PqForgeCipherSuite get cipherSuite;

  /// The backend that powers this engine.
  PqForgeEngineProvider get provider;

  /// Encrypts [plaintext], returning `ciphertext || tag` (tag appended).
  ///
  /// [key] must be [PqForgeCipherSuite.keyLength] bytes and [nonce] must be
  /// [PqForgeCipherSuite.nonceLength] bytes. [aad] is authenticated, not
  /// encrypted (pass an empty list for none).
  Future<Uint8List> seal({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
  });

  /// Decrypts a `ciphertext || tag` [cipherTextWithTag] body.
  ///
  /// Throws [PqForgeAuthTagException] if the tag (or bound [aad]) does not
  /// verify.
  Future<Uint8List> open({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List cipherTextWithTag,
    required Uint8List aad,
  });
}
