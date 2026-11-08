---
title: Envelopes
description: ML-KEM envelopes, streaming .pqfs, multi-recipient wrap, and the three profiles.
---

An envelope hides a payload under ML-KEM and AES-256-GCM. It does not
sign unless you pass a signer. SLH-DSA does not go inside an envelope.
Hybrid X25519 is a different call. HPKE is a different call. See
[HPKE](hpke) and [Signatures](signatures).

The `.pqf` and `.pqfs` layouts did not change in 0.4.11 or 0.4.12.

## Profiles

`PqForgeProfile` picks the ML-KEM set, the ML-DSA set, and the SLH-DSA set
that `keygen` uses when you do not name one.

| Profile | ML-KEM | ML-DSA | SLH-DSA default |
| --- | --- | --- | --- |
| `compact` | ML-KEM-512, category 1 | ML-DSA-44 | SHAKE-128f |
| `balanced` | ML-KEM-768, category 3 | ML-DSA-65 | SHAKE-192f |
| `maximum` | ML-KEM-1024, category 5 | ML-DSA-87 | SHAKE-256f |

ML-KEM sizes, in bytes:

| Set | Public | Secret | Ciphertext | Shared secret |
| --- | --- | --- | --- | --- |
| ML-KEM-512 | 800 | 1632 | 768 | 32 |
| ML-KEM-768 | 1184 | 2400 | 1088 | 32 |
| ML-KEM-1024 | 1568 | 3168 | 1568 | 32 |

ML-DSA sizes, in bytes:

| Set | Public | Secret | Signature |
| --- | --- | --- | --- |
| ML-DSA-44 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 2592 | 4896 | 4627 |

All 12 SLH-DSA sets exist for keygen, custody, and detached sign/verify.
The `s` sets are slow. The signatures are 8 to 50 KiB. That is why they
are not the envelope signature.

## One recipient, in memory

```dart
final forge = PqForge(profile: PqForgeProfile.balanced);
final keys = forge.generateKeys(keyId: 'desk');
final envelope = forge.encrypt(
  keys.kemKeyPair.publicKey,
  plaintext,
  aad: PqBytes.utf8Bytes('desk=records'),
);
final opened = forge.decrypt(
  keys.kemKeyPair.secretKey,
  envelope,
  aad: PqBytes.utf8Bytes('desk=records'),
);
```

`encrypt` encapsulates to the recipient public key, derives the DEM key
from the shared secret and the KEM ciphertext, and seals with AES-256-GCM.
The default associated data, when you omit `aad`, is the KEM ciphertext.
Pass the same bytes to `decrypt`.

`sealAndSign` adds an ML-DSA signature over the envelope. `sealToKemPublicKey`
is the same seal when you already hold a raw public key and do not want a
bundle. `openFromKemSecretKey` opens that shape.

`encrypt` rejects metadata keys reserved for another path (`hybridKex`,
`aeadSuite`, `recipients`). A sync envelope must not impersonate a hybrid
or a multi-recipient one.

## Typed payloads

These are envelopes with a recipe around the bytes. The cryptography is
the same AES-256-GCM envelope.

| Call | Opens with |
| --- | --- |
| `sealText` / `openText` | UTF-8 string |
| `sealEmail` / `openEmail` | mailbox bytes |
| `sealMedia` / `openMedia` | media bytes plus a media type |
| `encryptRecord` | a record id bound into the metadata |
| `encryptFolderEntry` / `decryptFolderEntry` | one file inside a folder seal |
| `encryptFileBytes` / `decryptFileBytes` | a whole buffer, still one shot |

Signing a document without encrypting it is `signDocument`, `signText`,
`signMedia`, and `signWebhook`. Those return a signature, not an envelope.

## More than one recipient

`PqMultiRecipient` wraps the same DEM key to each extra recipient. The
primary still decrypts the envelope. An additional recipient opens the
wrapped key entry and does not need the primary's secret.

`PqRecipientSpec` names the recipient public key and whether the wrap is
ML-KEM only or ML-KEM plus X25519. The entries live in envelope metadata
under `PqMultiRecipient.metadataKey`. `hasEntries` tells you the metadata
is that shape before you try to unwrap.

The CLI is `encrypt` with more than one `--recipient-public`. The first
recipient is the primary.

## Streaming

`.pqfs` is the streaming container. `PqStreamingHeader` is the pure,
web-safe framing: profile, KEM algorithm, KEM ciphertext, nonce salt,
frame size, and optional AAD hash. It does not contain the payload.
Frame counters are two big-endian uint32 halves, so the codec runs on
dart2js.

The `dart:io` engine that reads and writes files is
`PqForgeStreamCipher` in `package:pqforge/pqforge_io.dart`. The CLI uses
it once the input reaches 8 MiB (`streamingThresholdBytes`). Below that,
`encrypt` writes one `.pqf`. A browser can frame the same bytes over its
own transport with `PqStreamingEnvelope` and never import `dart:io`.

The memory gate in CI fails the build if the streaming path regresses past
1.5× payload amplification on a 64 MiB input. That is a regression check,
not a promise about every file you will ever seal.

## Hybrid KEM-DEM

`PqForgeAsync.encryptAsync` is ML-KEM plus X25519, then the combiner, then
an AEAD. `PqAeadSuite` selects AES-256-GCM or ChaCha20-Poly1305 for that
path. It is not RFC 9180. It is not X25519MLKEM768. The TLS hybrid is
pqtransport, and it calls `PqForgeCombiner` with the post-quantum share
first. See [Agreement](agreement).

[Keys](keys) · [Symmetric](symmetric) · [CLI](cli) · [Bytes](bytes)
