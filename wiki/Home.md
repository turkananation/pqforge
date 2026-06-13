# pqforge

`pqforge` is a pure-Dart, web-safe package for **post-quantum application
workflows**: encrypted files, folders, text, media, email payloads, records,
signed documents, signed webhooks, signed tokens, software artifacts,
gigabyte-scale streaming, multi-recipient envelopes, hybrid sessions, and
wrapped key custody — plus a universal CLI.

It is the **application layer** built on
[`pqcrypto`](https://pub.dev/packages/pqcrypto) (FIPS 203 ML-KEM, FIPS 204
ML-DSA). See [pqforge vs pqcrypto](pqforge-vs-pqcrypto) for the boundary.

## Pages

- [CLI Guide](CLI-Guide) — every command and flag
- [Recipe Catalog](Recipe-Catalog) — pick the surface for your app
- [Streaming And Large Files](Streaming-And-Large-Files) — gigabyte files, `pack`/`unpack`
- [Multi-Recipient And Hybrid](Multi-Recipient-And-Hybrid) — one ciphertext for many; PQC + X25519
- [Hybrid Sessions](Hybrid-Sessions) — X25519 + ML-KEM agreement, dual signatures
- [Key Custody](Key-Custody) — wrapped secret keys and stores
- [Performance](Performance) — engines, ciphers, measured throughput
- [pqforge vs pqcrypto](pqforge-vs-pqcrypto) — which package to use
- [Claim Boundary](Claim-Boundary) — what pqforge does and does not claim

## Fast CLI start

```bash
export PQFORGE_PASSPHRASE='load-this-from-a-secret-manager'

# Emits the full keyset by default: ML-KEM + ML-DSA + X25519 + Ed25519 + ECDSA-P256.
dart run pqforge keygen --profile maximum --key-id vault --out-dir keys \
  --passphrase-env PQFORGE_PASSPHRASE

# --hybrid adds an X25519 leg; large files auto-stream in bounded memory.
dart run pqforge encrypt-folder --hybrid \
  --recipient-public keys/vault.kem.public.json \
  --in-dir ./records --out-dir ./records.pqf

dart run pqforge decrypt-folder \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in-dir ./records.pqf --out-dir ./records.open
```

## What it provides

- ML-KEM KEM-DEM envelopes (`.pqf` one-shot, `.pqfs` streaming).
- ML-DSA signatures, plus hybrid ML-DSA + Ed25519/ECDSA-P256 and standalone ECDSA-P256.
- AES-256-GCM and ChaCha20-Poly1305 AEAD on a pure-Dart or native engine.
- X25519 + ML-KEM hybrid key agreement and hybrid KEM-DEM.
- Bounded-memory gigabyte streaming and whole-folder `pack`/`unpack`.
- Multi-recipient envelopes — one sealed payload, key-wrapped per recipient.
- Argon2id + AES-GCM wrapped key custody (PBKDF2 under FIPS mode).
- Named recipes and a universal CLI (18 commands) with AOT release binaries.

## Important boundary

`pqforge` composes cryptographic building blocks for applications. It is **not**
a CMVP/FIPS 140 validated module, and it does not provide public-key trust,
identity vetting, replay stores, authorization policy, TLS, or legal workflow
policy. Its post-quantum security claim is inherited from `pqcrypto`. See
[Claim Boundary](Claim-Boundary).
