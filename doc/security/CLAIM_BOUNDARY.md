# Claim Boundary

Allowed wording:

- FIPS 203-aligned ML-KEM through `pqcrypto`.
- FIPS 204-aligned ML-DSA through `pqcrypto`.
- FIPS 205-aligned SLH-DSA through `pqcrypto`. `pqforge` composes it into
  `keygen`, key custody, and detached `sign`/`verify`. Envelope headers,
  streaming signatures, and `hybrid-sign` remain ML-DSA-only.
- Application-layer composition helpers for KEM-DEM, AEAD sessions, wrapped key
  custody, signatures, recipes, hybrid helpers, X.509 certificates, PKCS#10
  requests, RFC 9180 HPKE, and CLI workflows. A certificate that `openssl req`
  can read is not a WebPKI CA and not a trust store. HPKE here is the RFC 9180
  composition over X25519, X448, P-256, P-384, and P-521, with HKDF-SHA256,
  HKDF-SHA384, HKDF-SHA512, and the AEADs the package implements. BoringSSL
  `EVP_HPKE` evidence is base and auth on X25519 and P-256 only. OpenSSL
  `OSSL_HPKE` evidence is all four modes on X448 and P-521 only. It is not a
  FIPS module and not TLS. X-Wing (`PqXWing`, `HpkeKem.xWing`, id
  `0x647A`, draft-connolly-cfrg-xwing-kem-11) is an additional KEM. It is
  not a FIPS construction. FIPS mode rejects it at `PqHpke` and
  `PqForgeHybridKeyAgreement`. Auth is not defined. It does not change
  `.pqf` or `.pqfs`. There is no BoringSSL or OpenSSL evidence for
  `0x647A`.
- `PqFipsMode` is a process-wide switch, not a validated module. It also
  rejects RSA-SHA-1 and an RSA modulus under 2048 bits at `PqRsa.signPkcs1`
  and `signPss` (verify returns false). HPKE seal and open refuse an AEAD
  other than AES-256-GCM. Background file helpers re-enable the flag in
  their isolate and refuse a custom `PqRandom.generator`. It does not gate
  Brainpool, FFDHE, AES-128-GCM at the primitive (QUIC Initial), a raw
  `PqForgeAeadEngine.seal`, or `PqXWing` itself.
- Brainpool ECDH (`PqBrainpool`) for brainpoolP256r1, brainpoolP384r1, and
  brainpoolP512r1, and RFC 7919 FFDHE (`PqFfdhe`) for the five named groups
  OpenSSL negotiates. BoringSSL does not negotiate these. The byte layout
  matches the TLS key share. `pqforge` does not speak TLS. Neither
  implementation is constant-time. The FFDHE exponent lives in a `BigInt`
  and is not wiped. The random buffer used to draw it is.
- Opt-in signature composition in the same release. `compose-sign` takes 2 or
  3 legs the caller names (ML-DSA, SLH-DSA, Ed25519, ECDSA-P256, ECDSA-P384,
  ECDSA-P521). `hybrid-sign` stays one ML-DSA leg plus one classical leg.
  `PqEcdsaP521` is a signature. It is not `p521SharedSecret` and not a TLS
  group. The P-521 HPKE share is unchanged.
- Best-effort cleanup in Dart.

Forbidden wording:

- FIPS validated.
- FIPS 140 validated.
- CMVP validated.
- Certified.
- Hard constant-time guarantee.
- Hard secure-erasure guarantee.
- ML-KEM alone is secure transport.
- AES signs documents.
- RC4 is supported.
- ECDSA-P521 is a TLS group, or is the HPKE P-521 KEM.
- `compose-sign` or ECDSA-P384/P-521 is constant-time or a FIPS module.
- SLH-DSA is an envelope signature or a `hybrid-sign` leg.
- Brainpool or FFDHE is a TLS stack, constant-time, or a NIST curve.
  There is no NIST P-512.
- BoringSSL 0.20261020.0 checks ML-KEM-512 or any SLH-DSA set other than
  SHA2-128s and SHAKE-256f. Those two, ML-KEM-768, ML-KEM-1024, and
  ML-DSA-44/65/87 are the sets that pin exports. The rest of SLH-DSA is
  an OpenSSL 4.1.0 check.
- X-Wing is a FIPS construction, a `.pqf` or `.pqfs` algorithm, or
  checked against BoringSSL or OpenSSL. Id `0x647A` has no such evidence.

`pqforge` can inherit algorithm-evidence wording from `pqcrypto`, but it must not
upgrade that into module-validation wording. Public-key trust, identity vetting,
authorization policy, replay stores, legal policy, and infrastructure custody
remain application responsibilities.

## Zeroization: what a wipe does and does not do

`pqforge` scrubs secret buffers through `package:zeroize`'s `secureZero`, which
uses an overwrite pattern plus `@pragma('vm:never-inline')` opaque read anchors
so Dead Store Elimination cannot prove the writes dead. A bare
`Uint8List.fillRange(0, n, 0)` is removable by the AOT compiler, because nothing
reads the buffer afterwards.

That is the whole of what a wipe buys, and the following are **not** claims:

- **A wipe is not erasure.** The runtime may hold another copy of the buffer —
  the GC can move it before disposal, and the old address is then never written.
  Pure Dart cannot `mlock` pages or exclude them from swap or core dumps.
- **A wipe cannot reach registers.** Values held in VM registers or spilled to
  stack slots are outside `secureZero`'s reach. Registers are spilled on context
  switch and can appear in core dumps and VM snapshots.
- **A wipe can, in principle, create a copy.** If the value being wiped is still
  needed *after* the wipe call, the compiler must preserve it across the call and
  may spill a second copy that the wipe does not cover. This is why every wipe
  site in `pqforge` is copy-then-wipe and never wipe-then-use, and why wiping a
  value that only ever lived in a register is pointless. See
  <https://00f.net/2026/10/06/zeroization-1/>.
- **Public values are not wiped.** `checkEncapsulationKey` deliberately does not
  wipe the ML-KEM ciphertext. Wiping non-secret data costs time and implies a
  sensitivity that does not exist.

Do not describe `secureZero` as guaranteeing that key material leaves memory,
and do not describe it as best-effort in a way that implies it can make the
situation worse than not calling it — for heap-resident buffers, which is all
`secureZero` accepts, it cannot.
