/// High-level secure session: cipher-suite selection, AEAD, and wire packets.
library;

import 'dart:typed_data';

import '../algorithms/pq_fips.dart';
import '../primitives/pq_primitives.dart';
import 'pq_cipher_suite.dart';
import 'pq_cryptography_aead_engine.dart';
import 'pq_pointycastle_aead_engine.dart';

/// Encrypts and decrypts application payloads into self-describing AEAD wire
/// packets, with an explicit choice of cipher suite and backend engine.
///
/// ```dart
/// final session = PqForgeSecureSession(
///   secretKey: derivedHybridKey,                       // 32 bytes
///   cipherSuite: PqForgeCipherSuite.chaCha20Poly1305,
///   engineProvider: PqForgeEngineProvider.pureDart,    // or .nativeCryptography
/// );
///
/// final packet = await session.encrypt(payload, associatedData: header);
/// final clear  = await session.decrypt(packet, associatedData: header);
/// session.dispose(); // wipe the key when finished
/// ```
///
/// ## Wire format
///
/// Every packet is a single contiguous byte array:
///
/// ```text
/// +-----------------------------+------------------------------------+
/// |      Nonce / IV (12 B)      |      Ciphertext + Tag (variable)   |
/// +-----------------------------+------------------------------------+
/// ```
///
/// [encrypt] generates a fresh cryptographically secure nonce, prepends it, and
/// appends the AEAD ciphertext-and-tag. [decrypt] slices the leading
/// [PqForgeCipherSuite.nonceLength] bytes back off as the nonce before
/// authenticating the remainder. Because both engines emit the identical
/// `ciphertext || tag` layout, a packet produced by one [PqForgeEngineProvider]
/// decrypts cleanly under the other.
final class PqForgeSecureSession {
  /// Creates a session bound to [secretKey], a [cipherSuite], and an
  /// [engineProvider] (defaults to [PqForgeEngineProvider.pureDart]).
  ///
  /// [secretKey] is defensively copied and must be exactly
  /// [PqForgeCipherSuite.keyLength] bytes (32); otherwise [ArgumentError] is
  /// thrown.
  PqForgeSecureSession({
    required Uint8List secretKey,
    required this.cipherSuite,
    this.engineProvider = PqForgeEngineProvider.pureDart,
  }) : _secretKey = Uint8List.fromList(secretKey),
       _engine = _resolveEngine(cipherSuite, engineProvider) {
    PqFipsMode.requireApprovedSuite(cipherSuite);
    cipherSuite.requireKey(_secretKey);
  }

  /// The negotiated AEAD cipher suite.
  final PqForgeCipherSuite cipherSuite;

  /// The backend performing the AEAD computation.
  final PqForgeEngineProvider engineProvider;

  final Uint8List _secretKey;
  final PqForgeAeadEngine _engine;
  bool _disposed = false;

  static PqForgeAeadEngine _resolveEngine(
    PqForgeCipherSuite suite,
    PqForgeEngineProvider provider,
  ) => switch (provider) {
    PqForgeEngineProvider.pureDart => PqForgePointyCastleAeadEngine(suite),
    PqForgeEngineProvider.nativeCryptography => PqForgeCryptographyAeadEngine(
      suite,
    ),
  };

  /// Encrypts [payload] into a `nonce || ciphertext || tag` wire packet.
  ///
  /// A fresh, cryptographically secure nonce is generated for every call — the
  /// caller must never supply or reuse one. [associatedData] (AAD) is bound
  /// into the authentication tag (protecting routing headers, session IDs,
  /// sequence numbers, …) but is not encrypted and is not included in the
  /// packet; the peer must supply the identical AAD to [decrypt].
  ///
  /// Throws [StateError] if the session has been [dispose]d.
  Future<Uint8List> encrypt(
    Uint8List payload, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();
    final nonce = PqBytes.randomBytes(cipherSuite.nonceLength);
    final body = await _engine.seal(
      key: _secretKey,
      nonce: nonce,
      plaintext: payload,
      aad: associatedData ?? _emptyAad,
    );
    return Uint8List(nonce.length + body.length)
      ..setRange(0, nonce.length, nonce)
      ..setRange(nonce.length, nonce.length + body.length, body);
  }

  /// Decrypts a wire packet produced by [encrypt] (from either backend).
  ///
  /// Slices off the leading [PqForgeCipherSuite.nonceLength] nonce bytes, then
  /// authenticates and decrypts the remainder using the same [associatedData]
  /// that was supplied to [encrypt]. The nonce and body are passed to the engine
  /// as zero-copy views over [packet]; the packet itself is never mutated.
  ///
  /// Throws [PqForgeAuthTagException] when authentication fails — a tampered
  /// nonce, ciphertext, or tag, or mismatched [associatedData]. Throws
  /// [ArgumentError] when [packet] is structurally too short to contain a nonce
  /// and a tag, and [StateError] if the session has been [dispose]d.
  Future<Uint8List> decrypt(
    Uint8List packet, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();
    final nonceLength = cipherSuite.nonceLength;
    final minLength = nonceLength + cipherSuite.tagLength;
    if (packet.length < minLength) {
      throw ArgumentError.value(
        packet.length,
        'packet',
        'must be at least $minLength bytes (nonce + tag)',
      );
    }
    return _engine.open(
      key: _secretKey,
      nonce: Uint8List.sublistView(packet, 0, nonceLength),
      cipherTextWithTag: Uint8List.sublistView(packet, nonceLength),
      aad: associatedData ?? _emptyAad,
    );
  }

  /// Zeroizes the session's internal copy of the secret key.
  ///
  /// After disposal the session can no longer [encrypt] or [decrypt]; either
  /// throws [StateError]. The caller's original key bytes are unaffected — the
  /// constructor took a defensive copy. Idempotent.
  void dispose() {
    _secretKey.fillRange(0, _secretKey.length, 0);
    _disposed = true;
  }

  void _ensureNotDisposed() {
    if (_disposed) {
      throw StateError('PqForgeSecureSession has been disposed');
    }
  }

  static final Uint8List _emptyAad = Uint8List(0);
}
