---
title: Recipes
description: Identity bindings, signed logs, tokens, artifacts, and the dual-signature policy.
---

A recipe is a signed structure with a fixed canonical message. The
signature is ML-DSA or, where the type allows it, one SLH-DSA set. It is
not an envelope. Encrypting the payload is a separate call. See
[Envelopes](envelopes).

You pass exactly one of `signatureAlgorithm` (ML-DSA) or `slhDsa`. Passing
both, or neither, throws `PqForgeException`. The signature length must be
that algorithm's `signatureBytes`.

## Types

| Type | What it binds |
| --- | --- |
| `PqIdentityBinding` | A subject id, an identity public key, `notBeforeMs`, and `expiresAtMs`. |
| `PqSignedLogEntry` | The previous entry's digest and this entry's body, so the log is a chain. |
| `PqArtifactSignature` | A digest of an artifact. The CLI pre-hashes with `sha256OfStream` so the file is not buffered. |
| `PqSignedToken` | A token id, an audience, and an expiry. `PqForge.issueToken` builds one. |
| `PqDualSignature` | Two signatures over one message. |
| `PqOffloadRequest` / `PqOffloadResponse` | The bytes a worker signs and the bytes it returns. The canonical form is `PqRecipeMessages`. |

`PqForge.createIdentityBinding` and `appendSignedLogEntry` are the facade
methods. They sign with the bundle's ML-DSA key unless you pass an SLH-DSA
key into the detached path. Envelope headers stay ML-DSA even if the
process also holds an SLH-DSA key.

## Dual policy

`PqDualSignaturePolicy.requireBoth` fails unless both signatures verify.
`acceptEither` succeeds when one does. `PqForgeSignatureComposer` is the
newer form of the same idea for two or three legs, including a classical
leg. `hybrid-sign` is not this. Hybrid-sign is exactly one ML-DSA and one
classical signature, and both must verify. See [Signatures](signatures).

The canonical bytes are what both sides sign. Do not sign the JSON you
stored unless `PqRecipeMessages` says that JSON is the message. A field
the canonical form omits is not authenticated.

[CLI](cli) · [Keys](keys) · [Bytes](bytes)
