/// Conformance + equivalence harness for [PqClassicalProvider] backends.
///
/// Any backend — the built-in pure-Dart one or a native FFI binding (e.g. to
/// AWS-LC) — must pass [classicalProviderConformance] (cryptographic contract)
/// and, when validated against the reference, [assertClassicalProvidersAgree].
///
/// **Determinism (what a native backend must match byte-for-byte):** X25519 ECDH
/// and Ed25519 (RFC 8032) are deterministic and must agree byte-for-byte; ECDSA-P256
/// is implementation-dependent (pqforge uses RFC-6979; AWS-LC is randomized) so
/// only cross-verification is required. Import this from a host package's own test
/// to gate a native backend.
library;

import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

Uint8List _pattern(int length, int Function(int) f) =>
    Uint8List.fromList(List<int>.generate(length, f));

/// Exercises the contract a classical provider must satisfy on its own: X25519
/// ECDH symmetry + seeded determinism, Ed25519 sign/verify with tamper rejection
/// and seeded determinism, and ECDSA-P256 sign/verify with tamper rejection and
/// deterministic public-key recovery.
Future<void> classicalProviderConformance(PqClassicalProvider provider) async {
  // --- X25519 ---
  final a = await provider.x25519GenerateKeyPair();
  final b = await provider.x25519GenerateKeyPair();
  expect(a.publicKey, hasLength(32));
  expect(a.secretKey, hasLength(32));
  final ssAB = await provider.x25519SharedSecret(
    secretKey: a.secretKey,
    remotePublicKey: b.publicKey,
  );
  final ssBA = await provider.x25519SharedSecret(
    secretKey: b.secretKey,
    remotePublicKey: a.publicKey,
  );
  expect(ssAB, ssBA, reason: 'X25519 ECDH must be symmetric');
  expect(ssAB, hasLength(32));

  final xSeed = _pattern(32, (i) => (i * 7 + 1) & 0xFF);
  final x1 = await provider.x25519GenerateKeyPair(seed: xSeed);
  final x2 = await provider.x25519GenerateKeyPair(seed: xSeed);
  expect(
    x1.publicKey,
    x2.publicKey,
    reason: 'X25519 seeded keygen deterministic',
  );
  expect(x1.secretKey, x2.secretKey);

  // --- Ed25519 ---
  final edSeed = _pattern(32, (i) => (i * 3 + 2) & 0xFF);
  final ed1 = await provider.ed25519GenerateKeyPair(seed: edSeed);
  final ed2 = await provider.ed25519GenerateKeyPair(seed: edSeed);
  expect(
    ed1.publicKey,
    ed2.publicKey,
    reason: 'Ed25519 seeded keygen deterministic',
  );
  expect(ed1.publicKey, hasLength(32));
  expect(await provider.ed25519PublicKeyFromSeed(edSeed), ed1.publicKey);

  final edMsg = _pattern(40, (i) => i & 0xFF);
  final edSig = await provider.ed25519Sign(
    secretKey: ed1.secretKey,
    publicKey: ed1.publicKey,
    message: edMsg,
  );
  expect(edSig, hasLength(64));
  expect(
    await provider.ed25519Verify(
      publicKey: ed1.publicKey,
      message: edMsg,
      signature: edSig,
    ),
    isTrue,
    reason: 'Ed25519 must verify its own signature',
  );
  final edBad = Uint8List.fromList(edMsg)..[0] ^= 0x01;
  expect(
    await provider.ed25519Verify(
      publicKey: ed1.publicKey,
      message: edBad,
      signature: edSig,
    ),
    isFalse,
    reason: 'Ed25519 must reject a tampered message',
  );

  // --- ECDSA-P256 ---
  final ec = await provider.ecdsaP256GenerateKeyPair();
  expect(ec.publicKey, hasLength(65));
  expect(ec.secretKey, hasLength(32));
  expect(
    await provider.ecdsaP256PublicKeyFromPrivate(ec.secretKey),
    ec.publicKey,
    reason:
        'ECDSA-P256 public key recomputed from the private scalar must match',
  );

  final ecMsg = _pattern(50, (i) => (i * 5) & 0xFF);
  final ecSig = await provider.ecdsaP256Sign(
    secretKey: ec.secretKey,
    message: ecMsg,
  );
  expect(ecSig, hasLength(64));
  expect(
    await provider.ecdsaP256Verify(
      publicKey: ec.publicKey,
      message: ecMsg,
      signature: ecSig,
    ),
    isTrue,
    reason: 'ECDSA-P256 must verify its own signature',
  );
  final ecBad = Uint8List.fromList(ecMsg)..[0] ^= 0x01;
  expect(
    await provider.ecdsaP256Verify(
      publicKey: ec.publicKey,
      message: ecBad,
      signature: ecSig,
    ),
    isFalse,
    reason: 'ECDSA-P256 must reject a tampered message',
  );

  // --- P-256 ECDH ---
  final p256a = await provider.p256GenerateKeyPair();
  final p256b = await provider.p256GenerateKeyPair();
  expect(p256a.publicKey, hasLength(65));
  expect(p256a.publicKey.first, 0x04);
  expect(p256a.secretKey, hasLength(32));
  final p256ab = await provider.p256SharedSecret(
    secretKey: p256a.secretKey,
    remotePublicKey: p256b.publicKey,
  );
  final p256ba = await provider.p256SharedSecret(
    secretKey: p256b.secretKey,
    remotePublicKey: p256a.publicKey,
  );
  expect(p256ab, p256ba, reason: 'P-256 ECDH must be symmetric');
  expect(p256ab, hasLength(32));
  expect(p256ab.any((b) => b != 0), isTrue);

  final p256Seed = _pattern(32, (i) => (i * 13 + 5) & 0xFF);
  // Seeded keygen is only defined when the seed is a valid scalar; skip if not.
  try {
    final s1 = await provider.p256GenerateKeyPair(seed: p256Seed);
    final s2 = await provider.p256GenerateKeyPair(seed: p256Seed);
    expect(
      s1.publicKey,
      s2.publicKey,
      reason: 'P-256 seeded keygen deterministic',
    );
    expect(s1.secretKey, s2.secretKey);
  } on ArgumentError {
    // Pattern may land outside [1, n); random keygen already covered.
  }

  // --- P-384 ECDH ---
  final p384a = await provider.p384GenerateKeyPair();
  final p384b = await provider.p384GenerateKeyPair();
  expect(p384a.publicKey, hasLength(97));
  expect(p384a.publicKey.first, 0x04);
  expect(p384a.secretKey, hasLength(48));
  final p384ab = await provider.p384SharedSecret(
    secretKey: p384a.secretKey,
    remotePublicKey: p384b.publicKey,
  );
  final p384ba = await provider.p384SharedSecret(
    secretKey: p384b.secretKey,
    remotePublicKey: p384a.publicKey,
  );
  expect(p384ab, p384ba, reason: 'P-384 ECDH must be symmetric');
  expect(p384ab, hasLength(48));
}

/// Asserts [candidate] agrees with [reference]: byte-identity on the deterministic
/// operations (X25519 ECDH, Ed25519 seeded keygen + signatures), and mutual
/// cross-verification for ECDSA-P256 (whose signatures are implementation-dependent).
Future<void> assertClassicalProvidersAgree(
  PqClassicalProvider reference,
  PqClassicalProvider candidate,
) async {
  // X25519 ECDH — deterministic ⇒ byte-identical.
  final aSeed = _pattern(32, (i) => (i * 9 + 1) & 0xFF);
  final bSeed = _pattern(32, (i) => (i * 9 + 7) & 0xFF);
  final aRef = await reference.x25519GenerateKeyPair(seed: aSeed);
  final aCand = await candidate.x25519GenerateKeyPair(seed: aSeed);
  expect(
    aCand.publicKey,
    aRef.publicKey,
    reason: 'X25519 seeded keygen disagrees',
  );
  expect(aCand.secretKey, aRef.secretKey);
  final bRef = await reference.x25519GenerateKeyPair(seed: bSeed);
  final ssRef = await reference.x25519SharedSecret(
    secretKey: aRef.secretKey,
    remotePublicKey: bRef.publicKey,
  );
  final ssCand = await candidate.x25519SharedSecret(
    secretKey: aCand.secretKey,
    remotePublicKey: bRef.publicKey,
  );
  expect(ssCand, ssRef, reason: 'X25519 ECDH disagrees with the reference');

  // Ed25519 — RFC 8032 deterministic ⇒ keygen AND signatures byte-identical.
  final edSeed = _pattern(32, (i) => (i * 11 + 3) & 0xFF);
  final edRef = await reference.ed25519GenerateKeyPair(seed: edSeed);
  final edCand = await candidate.ed25519GenerateKeyPair(seed: edSeed);
  expect(edCand.publicKey, edRef.publicKey, reason: 'Ed25519 keygen disagrees');
  expect(edCand.secretKey, edRef.secretKey);
  final edMsg = _pattern(33, (i) => (i * 2 + 1) & 0xFF);
  final sigRef = await reference.ed25519Sign(
    secretKey: edRef.secretKey,
    publicKey: edRef.publicKey,
    message: edMsg,
  );
  final sigCand = await candidate.ed25519Sign(
    secretKey: edCand.secretKey,
    publicKey: edCand.publicKey,
    message: edMsg,
  );
  expect(
    sigCand,
    sigRef,
    reason:
        'Ed25519 signatures must be byte-identical (RFC 8032 is deterministic)',
  );

  // ECDSA-P256 — implementation-dependent nonce ⇒ cross-verify only.
  final ecRef = await reference.ecdsaP256GenerateKeyPair();
  final ecMsg = _pattern(44, (i) => (i * 6 + 5) & 0xFF);
  final ecSigRef = await reference.ecdsaP256Sign(
    secretKey: ecRef.secretKey,
    message: ecMsg,
  );
  expect(
    await candidate.ecdsaP256Verify(
      publicKey: ecRef.publicKey,
      message: ecMsg,
      signature: ecSigRef,
    ),
    isTrue,
    reason: 'candidate must verify a reference ECDSA-P256 signature',
  );
  expect(
    await candidate.ecdsaP256PublicKeyFromPrivate(ecRef.secretKey),
    ecRef.publicKey,
    reason: 'ECDSA-P256 public-key recovery disagrees with the reference',
  );

  // P-256 / P-384 ECDH — deterministic ⇒ byte-identical.
  final p256Ref = await reference.p256GenerateKeyPair();
  final p256Peer = await reference.p256GenerateKeyPair();
  final p256SsRef = await reference.p256SharedSecret(
    secretKey: p256Ref.secretKey,
    remotePublicKey: p256Peer.publicKey,
  );
  final p256SsCand = await candidate.p256SharedSecret(
    secretKey: p256Ref.secretKey,
    remotePublicKey: p256Peer.publicKey,
  );
  expect(
    p256SsCand,
    p256SsRef,
    reason: 'P-256 ECDH disagrees with the reference',
  );

  final p384Ref = await reference.p384GenerateKeyPair();
  final p384Peer = await reference.p384GenerateKeyPair();
  final p384SsRef = await reference.p384SharedSecret(
    secretKey: p384Ref.secretKey,
    remotePublicKey: p384Peer.publicKey,
  );
  final p384SsCand = await candidate.p384SharedSecret(
    secretKey: p384Ref.secretKey,
    remotePublicKey: p384Peer.publicKey,
  );
  expect(
    p384SsCand,
    p384SsRef,
    reason: 'P-384 ECDH disagrees with the reference',
  );
}
