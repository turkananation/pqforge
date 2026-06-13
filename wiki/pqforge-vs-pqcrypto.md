# pqforge vs pqcrypto

`pqforge` and [`pqcrypto`](https://pub.dev/packages/pqcrypto) are sibling Dart
packages that solve **different layers** of the same problem. They are designed
to be used together: `pqforge` depends on `pqcrypto` and never reimplements the
post-quantum primitives.

## One sentence each

- **`pqcrypto` is the primitives.** Pure-Dart NIST FIPS 203 ML-KEM and FIPS 204
  ML-DSA, plus SHA-2 and SHA-3/SHAKE, with **zero runtime dependencies**. It
  gives you raw key generation, encapsulation/decapsulation, and sign/verify
  over byte arrays.
- **`pqforge` is the application toolkit.** It turns those primitives into
  encrypted files, folders, text, media, signed documents, webhooks, tokens,
  hybrid sessions, wrapped key custody, streaming, multi-recipient envelopes,
  and a CLI.

## Which one do I want?

| You want to… | Use |
| --- | --- |
| Call ML-KEM / ML-DSA directly over `Uint8List` | **pqcrypto** |
| Build your own protocol from the raw KEM/signature | **pqcrypto** |
| Encrypt a file, folder, or gigabyte media stream | **pqforge** |
| Sign a document, release artifact, webhook, or token | **pqforge** |
| Add an X25519/Ed25519/ECDSA-P256 hybrid leg | **pqforge** |
| Wrap secret keys with a passphrase (Argon2id + AES-GCM) | **pqforge** |
| Encrypt once for many recipients | **pqforge** |
| Ship a CLI to ops or a release pipeline | **pqforge** |

If you only need the algorithms, depend on `pqcrypto` and stop there. If you
need to **ship a feature**, reach for `pqforge`.

## What pqforge adds on top of pqcrypto

`pqcrypto` deliberately stops at the post-quantum primitives. `pqforge` supplies
the rest of the stack a real application needs:

- **KEM-DEM envelopes** — `.pqf` one-shot and `.pqfs` streaming containers.
- **Symmetric AEAD** — AES-256-GCM and ChaCha20-Poly1305, on a pure-Dart
  (PointyCastle) or native (`package:cryptography`) engine.
- **Classical hybrid tier** — X25519 key agreement, Ed25519 and ECDSA-P256
  signatures, combined with ML-KEM/ML-DSA so security holds if *either* the
  post-quantum or the classical assumption survives.
- **Key custody** — Argon2id + AES-256-GCM wrapped keys (PBKDF2 under FIPS mode)
  and pluggable stores.
- **Streaming and packing** — bounded-memory gigabyte files and one-archive
  folder `pack`/`unpack`.
- **Named recipes** — documents, text, media, email, records, logs, artifacts,
  identity bindings.
- **A universal CLI** plus AOT release binaries.

## What they share

- Both are **pure Dart and web-safe** — neither ships `dart:ffi` in its
  published package, so both run on the Dart VM, Flutter, and the web.
- Both prove byte-compatibility with the system OpenSSL using a separate,
  `publish_to: none` dev-only interop harness that is never shipped.
- Both refuse RC4 and unauthenticated encryption.

## Boundary it does not cross

`pqforge`'s post-quantum security claim is **inherited from `pqcrypto`**.
`pqforge` is not a CMVP/FIPS 140 validated module, and neither package provides
public-key trust, identity vetting, replay protection, authorization policy, or
TLS — those remain the application's responsibility. See
[Claim Boundary](Claim-Boundary).

## Links

- `pqcrypto` on pub.dev: <https://pub.dev/packages/pqcrypto>
- `pqcrypto` repository: <https://github.com/turkananation/pqcrypto>
- `pqforge` coverage audit against `pqcrypto`:
  [HYBRID_AUDIT.md](https://github.com/turkananation/pqforge/blob/main/doc/HYBRID_AUDIT.md)
