# pqforge

`pqforge` is a Dart package for post-quantum application workflows: encrypted
files, folders, text, media, email payloads, records, signed documents, signed
webhooks, signed tokens, software artifacts, hybrid sessions, and wrapped key
custody.

Start with:

- [CLI Guide](CLI-Guide)
- [Recipe Catalog](Recipe-Catalog)
- [Key Custody](Key-Custody)
- [Hybrid Sessions](Hybrid-Sessions)
- [Claim Boundary](Claim-Boundary)

## Fast CLI Start

```bash
export PQFORGE_PASSPHRASE='load-this-from-a-secret-manager'
dart run pqforge keygen --profile maximum --key-id vault --out-dir keys --passphrase-env PQFORGE_PASSPHRASE
dart run pqforge encrypt-folder --recipient-public keys/vault.kem.public.json --in-dir ./records --out-dir ./records.pqf
dart run pqforge decrypt-folder --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in-dir ./records.pqf --out-dir ./records.open
```

## What It Provides

- ML-KEM KEM-DEM envelopes.
- ML-DSA signatures.
- AES-256-GCM and ChaCha20-Poly1305 secure sessions.
- X25519 + ML-KEM hybrid key agreement.
- ML-DSA + Ed25519 hybrid signatures.
- Argon2id + AES-GCM wrapped keys.
- Named recipes and a universal CLI.

## Important Boundary

`pqforge` composes cryptographic building blocks for applications. It is not a
CMVP/FIPS 140 validated module, and it does not provide public-key trust,
identity vetting, replay stores, authorization policy, TLS, or legal workflow
policy.
