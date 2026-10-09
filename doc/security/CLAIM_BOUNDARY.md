# Claim Boundary

Allowed wording:

- FIPS 203-aligned ML-KEM through `pqcrypto`.
- FIPS 204-aligned ML-DSA through `pqcrypto`.
- FIPS 205-aligned SLH-DSA through `pqcrypto`. `pqforge` composes it into
  `keygen`, key custody, and detached `sign`/`verify`. Envelope headers,
  streaming signatures, and `hybrid-sign` remain ML-DSA-only.
- Application-layer composition helpers for KEM-DEM, AEAD sessions, wrapped key
  custody, signatures, recipes, hybrid helpers, and CLI workflows.
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
