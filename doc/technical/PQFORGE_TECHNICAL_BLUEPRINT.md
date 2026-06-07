# pqforge Technical Blueprint

Last updated: 2026-06-07

## Executive summary

`pqforge` is the reusable composition layer above `pqcrypto` and Pointy Castle.
It turns low-level post-quantum primitives into practical app workflows:
generate keys, sign documents, encrypt records/files, verify signed artifacts,
wrap keys with a passphrase, and exchange envelopes over files or APIs.

The package deliberately does not own user identity vetting, TLS, replay stores,
platform secure storage, cloud KMS, legal e-signature compliance, or FIPS 140
validation. It gives developers typed, tested building blocks that make those
application systems easier to wire correctly.

## Ecosystem gaps

Most packages sit at one of two extremes:

- primitives only: ML-KEM/ML-DSA are available, but every product reimplements
  envelopes, KDF binding, AAD handling, and file/API formats;
- application SDKs: storage, cloud, UI, or server choices are baked in too early.

`pqforge` fills the middle: stable pure-Dart composition APIs with portable
custody hooks and no platform lock-in.

## Supported capability matrix

| Capability | Source | pqforge role |
| --- | --- | --- |
| ML-KEM-512/768/1024 | `pqcrypto` | Keypair, encapsulate, decapsulate, sizes |
| ML-DSA-44/65/87 | `pqcrypto` | Sign, verify, prehash document/artifact flows |
| HKDF-SHA256 | Pointy Castle | KEM-DEM and hybrid session derivation |
| AES-GCM | Pointy Castle | Payload encryption and passphrase-wrapped keys |
| HMAC/SHA-256/SHA-256 | Pointy Castle | Hashing, AAD hashes, metadata binding |
| Argon2id | Pointy Castle | Passphrase-derived wrapping keys |
| Binary envelope v1 | `pqforge` | File/storage format |
| JSON/base64 envelope v1 | `pqforge` | API/server interchange format |
| Wrapped-key custody | `pqforge` | Passphrase vault plus app storage adapter |

## Package boundary

`pqforge` owns:

- algorithm metadata and strict length checks;
- primitive adapters over `pqcrypto` and Pointy Castle;
- binary and JSON envelope codecs;
- key bundle, export, wrapping, and storage interfaces;
- passphrase custody orchestration for app-supplied storage backends;
- document, record, file, log, artifact, identity, and dual-signature recipes.

Applications own:

- public-key trust and identity enrollment decisions;
- classical KEX material for hybrid sessions;
- replay windows, sessions, TLS, routing, and storage;
- platform secure storage, KMS/HSM, and operator custody;
- regulatory and certification claims.

## Envelope formats

Binary v1 is the default for files and storage. JSON/base64 v1 is the default
for APIs, Serverpod DTOs, webhooks, logs, and debugging. Both carry version,
profile, algorithm IDs, nonce, KEM ciphertext, payload, optional AAD hash,
optional signer key ID, optional ML-DSA signature, and JSON-safe metadata.

## Real-world use cases

- Government records: encrypt records with the maximum profile and tenant AAD.
- Medical records: bind patient/tenant context through AAD and metadata.
- Document signing: sign canonical document bytes with a versioned context.
- Startup SaaS: sign webhooks, licenses, release artifacts, and API tokens.
- File vaults: encrypt bytes to a vault public key without forcing local storage.
- CI release provenance: sign artifact hashes and version metadata.

## Delivery milestones

See `doc/roadmap/ROADMAP.md` and `doc/roadmap/PROJECT_TRACKER.md`.

## Claim boundary

Use evidence-scoped wording only. `pqforge` may say it composes FIPS
203-aligned ML-KEM and FIPS 204-aligned ML-DSA through `pqcrypto`; it must not
claim CMVP/FIPS 140 validation, certification, hard constant-time execution, or
hard memory-erasure guarantees.
