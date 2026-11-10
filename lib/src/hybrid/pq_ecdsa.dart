/// One ECDSA implementation for P-256, P-384, and P-521.
///
/// The public types stay separate so a P-256 key cannot be passed where a
/// P-384 key is required. RFC 6979 nonces, low-S on sign, high-S accepted
/// on verify. Not a constant-time implementation.
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'pq_scalar.dart';

/// Parameterized NIST ECDSA. [newDigest] must return a fresh digest each call.
final class PqEcdsaCurve {
  PqEcdsaCurve({
    required this.domain,
    required this.privateKeyBytes,
    required this.publicKeyBytes,
    required this.signatureBytes,
    required this.newDigest,
    required this.hmacBlockBytes,
  });

  final pc.ECDomainParameters domain;
  final int privateKeyBytes;
  final int publicKeyBytes;
  final int signatureBytes;
  final pc.Digest Function() newDigest;
  final int hmacBlockBytes;

  ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() {
    final generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(domain),
          pqSeededFortuna(),
        ),
      );
    final pair = generator.generateKeyPair();
    return (
      secretKey: pqFixedBigInt(pair.privateKey.d!, privateKeyBytes),
      publicKey: pair.publicKey.Q!.getEncoded(false),
    );
  }

  Uint8List publicKeyFromPrivate(Uint8List privateKey) {
    if (privateKey.length != privateKeyBytes) {
      throw ArgumentError.value(
        privateKey.length,
        'privateKey',
        'expected $privateKeyBytes bytes',
      );
    }
    final d = pqBigIntFromBytes(privateKey);
    if (d < BigInt.one || d >= domain.n) {
      throw ArgumentError.value(
        privateKey,
        'privateKey',
        'scalar is not in the range [1, n)',
      );
    }
    final q = domain.G * d;
    if (q == null || q.isInfinity) {
      throw ArgumentError.value(
        privateKey,
        'privateKey',
        'derived point at infinity',
      );
    }
    return q.getEncoded(false);
  }

  Uint8List sign({required Uint8List privateKey, required Uint8List message}) {
    if (privateKey.length != privateKeyBytes) {
      throw ArgumentError.value(
        privateKey.length,
        'privateKey',
        'expected $privateKeyBytes bytes',
      );
    }
    final signer =
        pc.NormalizedECDSASigner(
          pc.ECDSASigner(newDigest(), pc.HMac(newDigest(), hmacBlockBytes)),
          enforceNormalized: true,
        )..init(
          true,
          pc.PrivateKeyParameter<pc.ECPrivateKey>(
            pc.ECPrivateKey(pqBigIntFromBytes(privateKey), domain),
          ),
        );
    final signature = signer.generateSignature(message) as pc.ECSignature;
    final half = signatureBytes ~/ 2;
    return Uint8List(signatureBytes)
      ..setRange(0, half, pqFixedBigInt(signature.r, half))
      ..setRange(half, signatureBytes, pqFixedBigInt(signature.s, half));
  }

  bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    final encoded = normalizePoint(publicKey);
    if (encoded == null || signature.length != signatureBytes) return false;
    try {
      final point = domain.curve.decodePoint(encoded);
      if (point == null || point.isInfinity) return false;
      final verifier =
          pc.ECDSASigner(newDigest(), pc.HMac(newDigest(), hmacBlockBytes))
            ..init(
              false,
              pc.PublicKeyParameter<pc.ECPublicKey>(
                pc.ECPublicKey(point, domain),
              ),
            );
      final half = signatureBytes ~/ 2;
      final r = pqBigIntFromBytes(Uint8List.sublistView(signature, 0, half));
      final s = pqBigIntFromBytes(
        Uint8List.sublistView(signature, half, signatureBytes),
      );
      if (r == BigInt.zero ||
          s == BigInt.zero ||
          r >= domain.n ||
          s >= domain.n) {
        return false;
      }
      return verifier.verifySignature(message, pc.ECSignature(r, s));
    } catch (_) {
      return false;
    }
  }

  /// Uncompressed `0x04 || X || Y`, or null when [encoded] is not on [domain].
  ///
  /// Accepts the compressed SEC1 forms. Hybrid `0x06` / `0x07` is rejected.
  Uint8List? normalizePoint(Uint8List encoded) {
    if (encoded.isEmpty) return null;
    final tag = encoded[0];
    final compressed = tag == 0x02 || tag == 0x03;
    if (tag != 0x04 && !compressed) return null;
    final expected = compressed ? (publicKeyBytes ~/ 2) + 1 : publicKeyBytes;
    if (encoded.length != expected) return null;
    try {
      final point = domain.curve.decodePoint(encoded);
      if (point == null || point.isInfinity) return null;
      final raw = point.getEncoded(false);
      if (raw.length != publicKeyBytes || raw[0] != 0x04) return null;
      return Uint8List.fromList(raw);
    } catch (_) {
      return null;
    }
  }
}
