# pqforge

Post-quantum application recipes for Dart, Flutter, Serverpod, and local CLI
workflows.

## Project Signals

[![pub package](https://img.shields.io/badge/pub.dev-pqforge-0175c2?style=for-the-badge&logo=dart&logoColor=white)](https://pub.dev/packages/pqforge)
[![API docs](https://img.shields.io/badge/API-reference-0ea5e9?style=for-the-badge&logo=dart&logoColor=white)](https://pub.dev/documentation/pqforge/latest/)
[![GitHub Pages](https://img.shields.io/badge/Pages-use_cases_site-52e0d5?style=for-the-badge&logo=githubpages&logoColor=0b1220)](https://turkananation.github.io/pqforge/)
[![Wiki](https://img.shields.io/badge/Wiki-recipes_%26_CLI-f5c35b?style=for-the-badge&logo=wikipedia&logoColor=0b1220)](https://github.com/turkananation/pqforge/wiki)

## Cryptographic Surface

[![ML-KEM](https://img.shields.io/badge/FIPS_203-ML--KEM_512_768_1024-2f855a?style=for-the-badge)](doc/HYBRID_AUDIT.md)
[![ML-DSA](https://img.shields.io/badge/FIPS_204-ML--DSA_44_65_87-2f855a?style=for-the-badge)](doc/HYBRID_AUDIT.md)
[![AEAD](https://img.shields.io/badge/AEAD-AES--GCM_%7C_ChaCha20--Poly1305-7c3aed?style=for-the-badge)](doc/API.md)
[![Hybrid](https://img.shields.io/badge/Hybrid-X25519_%2B_ML--KEM-f97316?style=for-the-badge)](doc/decisions/ADR-0002-optional-classical-hybrid-tier.md)

## Automation And Discovery

[![CI](https://img.shields.io/badge/CI-format_analyze_test_cli-111827?style=for-the-badge&logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
[![Pages workflow](https://img.shields.io/badge/Workflow-Pages-111827?style=for-the-badge&logo=githubactions&logoColor=white)](.github/workflows/pages.yml)
[![Wiki sync](https://img.shields.io/badge/Workflow-Wiki_sync-111827?style=for-the-badge&logo=githubactions&logoColor=white)](.github/workflows/sync-wiki.yml)
[![llms.txt](https://img.shields.io/badge/AI-llms.txt-7c3aed?style=for-the-badge)](llms.txt)

`pqforge` turns `pqcrypto` ML-KEM and ML-DSA primitives into practical,
domain-separated application workflows: encrypted files, folders, text, media,
email payloads, records, signed documents, signed webhooks, signed tokens,
release artifacts, tamper-evident logs, hybrid sessions, wrapped key custody,
and a reusable CLI.

It is deliberately more than "call a primitive." It gives users named,
auditable operations they can explain in a code review.

## First Run

```bash
dart pub get

export PQFORGE_PASSPHRASE='load-this-from-a-secret-manager'
dart run pqforge keygen \
  --profile maximum \
  --key-id vault \
  --out-dir keys \
  --passphrase-env PQFORGE_PASSPHRASE

dart run pqforge encrypt-folder \
  --recipient-public keys/vault.kem.public.json \
  --in-dir ./records \
  --out-dir ./records.pqf

dart run pqforge decrypt-folder \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in-dir ./records.pqf \
  --out-dir ./records.open
```

`keygen --out-dir` stores reusable keys in the selected directory. Public keys
are raw JSON. Secret keys are Argon2id + AES-256-GCM wrapped JSON when you pass
`--passphrase-env`, `--passphrase-file`, or `--passphrase`.

## What You Can Build

| App idea | Use this surface |
| --- | --- |
| Local file vaults and server export jobs | `encrypt`, `decrypt`, `encryptFileBytes` |
| Folder archives and evidence bundles | `encrypt-folder`, `decrypt-folder`, `encryptFolderEntry` |
| Notes, prompts, and short secrets | `encrypt-text`, `decrypt-text`, `sealText`, `signText` |
| Images, audio, video, PDFs, and media records | `encrypt-media`, `decrypt-media`, `sealMedia`, `signMedia` |
| Contracts, approvals, certificates, and reports | `sign --kind document`, `signDocument` |
| Payment callbacks and server events | `signWebhook`, `verifyWebhook` |
| API capability grants and admin actions | `issueToken`, `verifyToken` |
| Secure notification bodies | `sealEmail`, `openEmail` |
| Medical, government, and registry records | `encryptRecord`, `appendSignedLogEntry` |
| Release bundles and firmware | `sign --kind artifact`, `signArtifact` |
| Serverpod/API hybrid sessions | `PqForgeHybridKeyAgreement`, `PqForgeSecureSession` |

The full app catalog is in [doc/cookbook/PROJECT_CATALOG.md](doc/cookbook/PROJECT_CATALOG.md).

## Library Quickstart

```dart
import 'dart:typed_data';
import 'package:pqforge/pqforge.dart';

final forge = PqForge(profile: PqForgeProfile.maximum);
final keys = forge.generateKeys(keyId: 'archive-key');

final envelope = forge.sealMedia(
  keys.kemKeyPair.publicKey,
  mediaBytes,
  mediaId: 'cover-2026-001',
  mimeType: 'image/png',
);

final opened = forge.openMedia(
  keys.kemKeyPair.secretKey,
  envelope,
);

final signature = forge.signArtifact(
  signerSecretKey: keys.signatureKeyPair.secretKey,
  artifactId: 'release.tar.gz',
  version: 7,
  artifactBytes: Uint8List.fromList(opened),
);
```

## CLI Commands

| Command | Purpose |
| --- | --- |
| `keygen` | Generate public keys and raw or wrapped secret keys |
| `encrypt` / `decrypt` | Encrypt and decrypt a single file |
| `encrypt-folder` / `decrypt-folder` | Encrypt and decrypt folder trees |
| `encrypt-text` / `decrypt-text` | Encrypt and decrypt UTF-8 text |
| `encrypt-media` / `decrypt-media` | Encrypt and decrypt media or PDFs |
| `sign` / `verify` | Sign and verify documents, text, media, and artifacts |

Read the complete command guide at [doc/CLI.md](doc/CLI.md).

## Profiles

| Profile | KEM | Signature | Best for |
| --- | --- | --- | --- |
| `compact` | ML-KEM-512 | ML-DSA-44 | smaller demos and constrained payloads |
| `balanced` | ML-KEM-768 | ML-DSA-65 | default application and server workflows |
| `maximum` | ML-KEM-1024 | ML-DSA-87 | long-lived records, archives, media, and high-value artifacts |

## Hybrid Sessions

The optional `package:pqforge/pqforge_cryptography.dart` entrypoint adds:

- `PqForgeHybridKeyAgreement` for X25519 + ML-KEM session key agreement;
- `PqForgeHybridSigner` for ML-DSA + Ed25519 dual signatures;
- `PqForgeSecureSession` for AES-256-GCM or ChaCha20-Poly1305 packets;
- `SecretKey.deriveHybridSecretKey()` for `package:cryptography` users.

ECDSA remains app-supplied through `dualSign` / `dualVerify` because
`cryptography 2.9.0` exposes P-256 but does not implement Dart VM key generation
for that path.

## Claim Boundary

Allowed:

- "FIPS 203-aligned ML-KEM through `pqcrypto`."
- "FIPS 204-aligned ML-DSA through `pqcrypto`."
- "Application-layer composition helpers for KEM-DEM, AEAD sessions, wrapped
  key custody, signatures, recipes, and CLI workflows."

Do not claim:

- "FIPS validated", "CMVP validated", or "certified";
- hard constant-time Dart behavior;
- hard memory erasure;
- "ML-KEM alone is secure transport";
- AES signs documents;
- RC4 support.

RC4 is not supported. AES is encryption, not signatures.

## Documentation

- [GitHub Pages use-case site](https://turkananation.github.io/pqforge/)
- [Documentation index](doc/INDEX.md)
- [CLI guide](doc/CLI.md)
- [Project catalog](doc/cookbook/PROJECT_CATALOG.md)
- [Cookbook](doc/cookbook/README.md)
- [API reference](doc/API.md)
- [Hybrid audit](doc/HYBRID_AUDIT.md)
- [Key custody](doc/architecture/KEY_CUSTODY.md)
- [Claim boundary](doc/security/CLAIM_BOUNDARY.md)
- [Visibility generation](tool/visibility/README.md)

## Validation

```bash
dart run tool/visibility/generate_visibility.dart --check
dart format --output=none --set-exit-if-changed .
dart analyze
dart test
dart run example/pqforge_example.dart
dart run example/catalog_recipes_example.dart
dart run example/hybrid_key_agreement_example.dart
dart pub publish --dry-run
```
