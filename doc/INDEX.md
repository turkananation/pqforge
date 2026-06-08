# pqforge Documentation Index

This is the canonical documentation map for `pqforge`. Use `doc/` links for
project documentation, `site/` for the generated GitHub Pages surface, and
`wiki/` for the GitHub Wiki source.

## Start Here

| Need | Document |
| --- | --- |
| Package overview and selling points | [../README.md](../README.md) |
| Full CLI usage | [CLI.md](CLI.md) |
| API reference | [API.md](API.md) |
| App and project catalog | [cookbook/PROJECT_CATALOG.md](cookbook/PROJECT_CATALOG.md) |
| Recipe cookbook | [cookbook/README.md](cookbook/README.md) |
| Hybrid coverage audit | [HYBRID_AUDIT.md](HYBRID_AUDIT.md) |
| Key custody | [architecture/KEY_CUSTODY.md](architecture/KEY_CUSTODY.md) |
| Claim boundary | [security/CLAIM_BOUNDARY.md](security/CLAIM_BOUNDARY.md) |
| GitHub Pages and AI discovery generation | [../tool/visibility/README.md](../tool/visibility/README.md) |

## Package Surface

| Area | Coverage |
| --- | --- |
| PQC primitives | ML-KEM-512/768/1024 and ML-DSA-44/65/87 through `pqcrypto` |
| Encryption | KEM-DEM envelopes plus AES-256-GCM secure sessions |
| Sessions | AES-256-GCM and ChaCha20-Poly1305 packet sessions |
| Hybrid transition | X25519 + ML-KEM agreement and ML-DSA + Ed25519 signatures |
| Key custody | Argon2id + AES-GCM wrapped keys and pluggable stores |
| CLI | file, folder, text, media, signing, verification, and wrapped key reuse |
| Recipes | documents, text, media, email, webhooks, tokens, records, logs, artifacts, identity bindings |

## Generated Visibility

The generated visibility files are controlled by
[`tool/visibility/visibility_manifest.json`](../tool/visibility/visibility_manifest.json).
After editing the manifest, run:

```bash
dart run tool/visibility/generate_visibility.dart
dart run tool/visibility/generate_visibility.dart --check
```

The generated root files are copied into `site/` so GitHub Pages and AI
discovery surfaces stay consistent.
