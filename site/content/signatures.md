---
title: Signatures
description: Opt-in ML-DSA, SLH-DSA, and ECDSA legs. Dual and triple compose-sign.
---

This page is the 0.4.10 signature rollout. It does not replace
[HPKE](hpke), [Certificates](certificates), [Symmetric](symmetric), or
[Classical](classical). Those pages stay the source for encapsulation,
X.509, AEAD, and ECDH.

## What was already there

- Detached ML-DSA, including recipe `sign` for a document, text, media, or
  artifact.
- `hybrid-sign`: one ML-DSA leg plus one classical leg. That classical leg
  was Ed25519 or ECDSA-P256.
- Standalone `ecdsa-sign` for ECDSA-P256 (RFC 6979, low-S).
- SLH-DSA on `keygen` and on detached `sign` / `verify`.
- Envelope signatures and `.pqfs` header signatures stay ML-DSA. `hybrid-sign`
  does not take an SLH-DSA key.

## What this release adds

Detached recipes now take `slhDsa:` as well as ML-DSA. That includes
documents, text, media, webhooks, artifacts, `issueToken`,
`appendSignedLogEntry`, and `createIdentityBinding`. Pass one of the two,
not both. An ML-DSA token from 0.4.9 still verifies. Token JSON stays
version 1. CLI `sign --kind webhook` needs `--event-type`. The CLI does
not enforce a replay window.

`compose-sign` is 2 legs (dual) or 3 (triple). Each flag is one algorithm.
Nothing is implied.

| Flag | Leg |
| --- | --- |
| `--ml-dsa-secret` | the ML-DSA set in that key |
| `--slh-secret` | the SLH-DSA set in that key |
| `--classical-secret` | Ed25519, ECDSA-P256, ECDSA-P384, or ECDSA-P521. Repeatable |

`--policy require-all` is the default. `--policy accept-any` succeeds when
one leg verifies.

`keygen --classical ecdsa-p384` and `--classical ecdsa-p521` emit those
keys. They are not in the default classical set. That default is still
X25519, Ed25519, and ECDSA-P256. `ecdsa-sign` follows the key.
`hybrid-sign` is still exactly one ML-DSA leg plus one classical leg, and
that classical leg may now be P-384 or P-521.

`PqEcdsaP521` signs. It is not `PqNistEcdh.p521SharedSecret`. The P-521
ECDH share is still the HPKE KEM share, and it is still not a TLS group.
P-384 and P-521 ECDSA are not methods on `PqClassicalProvider`.

None of this is constant-time. None of it changes `.pqf` or `.pqfs`.
