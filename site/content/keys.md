---
title: Keys
description: Keygen, Argon2id and PBKDF2 wrap, and pluggable custody.
---

`PqForge.generateKeys` mints the bundle a profile names: an ML-KEM pair,
an ML-DSA pair, and the bookkeeping those envelopes expect. One algorithm
at a time is `generateKemKeyPair`, `generateSignatureKeyPair`,
`generateSignatureKeyPairFromSeed`, and `generateSlhDsaKeyPair`.

`generateSignatureKeyPairFromSeed` takes the 32-byte ML-DSA seed. The same
seed produces the same key. Treat the seed as the secret. SLH-DSA keygen
takes its own seeds inside pqcrypto. The pqforge call
`generateSlhDsaKeyPair` draws them.

Exported keys are `PqExportedKey`. A pair is `PqKeyPair`. A profile bundle
is `PqKeyBundle`. `PqKeyKind` tells the CLI and the custody layer which
file they are looking at.

## Passphrase wrap

`wrapKeyWithPassphrase` derives a wrapping key and seals the exported
secret with AES-256-GCM. The key identity is the associated data, so a
wrapped blob cannot be silently retargeted at another key id.

| KDF | Constant | When |
| --- | --- | --- |
| Argon2id | `PqKdf.argon2id` | Default. Not FIPS-approved. |
| PBKDF2-HMAC-SHA256 | `PqKdf.pbkdf2HmacSha256` | Required while `PqFipsMode` is on. |

Argon2id defaults are 2 iterations, memory `2^16` KiB, 4 lanes. PBKDF2
defaults to 600000 iterations. Both take a fresh 16-byte salt and a fresh
AES-GCM nonce. `unwrapKeyWithPassphrase` is the inverse. A wrong
passphrase fails the AES-GCM tag. It does not return a partial key.

`PqFipsMode` is a process-wide switch you set once at startup. It refuses
ChaCha20-Poly1305 on `PqForgeSecureSession` and `PqForgeStreamCipher`, and
it refuses Argon2id on wrap. Turning it on does not make this package a
validated module. See [Claim boundary](claim-boundary).

## Custody

`PqPassphraseKeyCustody` is wrap plus a store.

| Store | Behavior |
| --- | --- |
| `PqMemoryKeyCustodyStore` | Process memory. Lost when the isolate exits. |
| `PqCallbackKeyCustodyStore` | Your `put`, `get`, and `delete`. |
| `PqKeyCustodyStore` | The interface both implement. |

```dart
final custody = PqPassphraseKeyCustody(
  forge: forge,
  store: PqMemoryKeyCustodyStore(),
);
await custody.wrapAndPut(exported, passphrase);
final opened = await custody.getAndUnwrap(storageId, passphrase);
```

`putWrappedKey` stores a blob you already wrapped. `requireWrappedKey`
throws when the id is absent. `delete` removes the document. The store
sees JSON, not the raw secret. The secret exists only between unwrap and
the moment you wipe your copy. `package:zeroize` is best-effort. The Dart
runtime may already have copied the bytes.

`PqKeyStore` and `PqKeyResolver` are the narrower interfaces the envelope
path uses when it must find a public key by id. They are not a database.

[Envelopes](envelopes) · [CLI](cli) · [Bytes](bytes)
