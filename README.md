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

The core (`package:pqforge/pqforge.dart`) is **pure Dart and web-safe** — no
`dart:ffi`, so the same code runs on the Dart VM, Flutter (with optional
hardware-backed AEAD), and the web. Gigabyte-scale file streaming lives behind
the `dart:io` entrypoint `package:pqforge/pqforge_io.dart`.

## Built on pqcrypto

`pqforge` is the **application layer**;
[`pqcrypto`](https://pub.dev/packages/pqcrypto)
([repo](https://github.com/turkananation/pqcrypto)) is the **primitives layer**.

- **`pqcrypto`** gives you pure-Dart FIPS 203 ML-KEM and FIPS 204 ML-DSA (plus
  SHA-2/3) with zero runtime dependencies — raw keygen, encaps/decaps, sign/verify
  over bytes. Reach for it when you need the algorithms and nothing else.
- **`pqforge`** depends on `pqcrypto` and never reimplements the lattice
  primitives. It adds everything you need to *ship a feature*: KEM-DEM envelopes,
  AES-256-GCM/ChaCha20-Poly1305 AEAD, X25519/Ed25519/ECDSA-P256 hybrids,
  streaming, multi-recipient envelopes, key custody, recipes, and a CLI.

`pqforge`'s post-quantum security claim is inherited from `pqcrypto`. Full
breakdown: [pqforge vs pqcrypto](https://github.com/turkananation/pqforge/wiki/pqforge-vs-pqcrypto)
· [doc/HYBRID_AUDIT.md](doc/HYBRID_AUDIT.md).

## First Run

```bash
dart pub get

export PQFORGE_PASSPHRASE='load-this-from-a-secret-manager'

# Generates the full keyset by default: ML-KEM + ML-DSA, plus X25519 (hybrid
# encryption) and Ed25519/ECDSA-P256 (hybrid signing). Secret keys are wrapped.
dart run pqforge keygen \
  --profile maximum \
  --key-id vault \
  --out-dir keys \
  --passphrase-env PQFORGE_PASSPHRASE

# --hybrid adds an X25519 leg, so confidentiality holds as long as EITHER
# ML-KEM or X25519 stands. Large files auto-stream in bounded memory.
dart run pqforge encrypt-folder --hybrid \
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
`--passphrase-env`, `--passphrase-file`, or `--passphrase`. `--no-classical`
emits only the ML-KEM/ML-DSA bundle.

Inspect any artifact without decrypting it:

```bash
dart run pqforge inspect --in ./records.pqf/report.txt.pqf
# → format, profile, suite (e.g. ML-KEM-1024 + X25519 → HKDF-SHA-512 →
#   AES-256-GCM), signature, recipients, and metadata
```

## What You Can Build

Every row is post-quantum where it counts. The **Powered by** column names the
engine doing the work — read `🛡️ → 🔒` as "wrap a quantum-safe key, then encrypt
the bytes with it":

- 🛡️ **`pqcrypto`** — pure-Dart PQC: ML-KEM (FIPS 203), ML-DSA (FIPS 204)
- 🔒 **`PointyCastle`** — pure-Dart classical: AES-256-GCM, ChaCha20-Poly1305, HKDF, Argon2id, ECDSA-P256
- 🤝 **`cryptography`** — native/optimized classical: X25519, Ed25519

| App idea | Use this surface | Powered by |
| --- | --- | --- |
| Local file vaults and server export jobs | `encrypt`, `decrypt`, `encryptFileBytes` | 🛡️ ML-KEM → 🔒 AES-256-GCM (KEM-DEM via HKDF) |
| Defence-in-depth at rest (PQC + classical) | `encrypt --hybrid`, `encryptAsync` | 🤝 X25519 + 🛡️ ML-KEM → 🔒 AES-256-GCM |
| One ciphertext for many readers | `encrypt --recipient-public … --recipient-public …` | 🛡️ ML-KEM key-wrap per recipient, payload sealed once |
| Gigabyte files and media, bounded memory | `encrypt`/`encrypt-media` (auto `.pqfs` ≥ 8 MiB), `PqForgeStreamCipher` | 🛡️ ML-KEM → 🔒 AES-256-GCM, framed |
| Many tiny files in one archive | `pack`, `unpack` | one 🛡️ ML-KEM + one 🛡️ ML-DSA for the whole tree |
| Folder archives and evidence bundles | `encrypt-folder`, `decrypt-folder`, `encryptFolderEntry` | 🛡️ ML-KEM → 🔒 AES-256-GCM per entry |
| Notes, prompts, and short secrets | `encrypt-text`, `decrypt-text`, `sealText`, `signText` | seal 🛡️ ML-KEM → 🔒 AES-256-GCM · sign 🛡️ ML-DSA |
| Images, audio, video, PDFs, and media records | `encrypt-media`, `decrypt-media`, `sealMedia`, `signMedia` | seal 🛡️ ML-KEM → 🔒 AES-256-GCM · sign 🛡️ ML-DSA |
| Contracts, approvals, certificates, and reports | `sign --kind document`, `signDocument` | 🛡️ ML-DSA (FIPS 204) |
| Payment callbacks and server events | `signWebhook`, `verifyWebhook` | 🛡️ ML-DSA + timestamp/nonce binding |
| API capability grants and admin actions | `issueToken`, `verifyToken` | 🛡️ ML-DSA over canonical claims |
| Secure notification bodies | `sealEmail`, `openEmail` | 🛡️ ML-KEM → 🔒 AES-256-GCM |
| Medical, government, and registry records | `encryptRecord`, `appendSignedLogEntry` | seal 🛡️ ML-KEM → 🔒 AES-256-GCM · log 🛡️ ML-DSA hash chain |
| Release bundles and firmware | `sign --kind artifact`, `hybrid-sign --digest` | 🛡️ ML-DSA (pre-hash) [+ 🤝 Ed25519 \| 🔒 ECDSA-P256] |
| Serverpod/API hybrid sessions | `PqForgeHybridKeyAgreement`, `PqForgeSecureSession` | 🤝 X25519 + 🛡️ ML-KEM → 🔒 AEAD |
| Hybrid signatures (PQC + classical) | `PqForgeHybridSigner` | 🛡️ ML-DSA + (🤝 Ed25519 \| 🔒 ECDSA-P256) |

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
| `keygen` | Generate the full keyset (ML-KEM/ML-DSA + X25519/Ed25519/ECDSA-P256) by default |
| `encrypt` / `decrypt` | Encrypt and decrypt a single file (auto-streams ≥ 8 MiB) |
| `encrypt-folder` / `decrypt-folder` | Encrypt and decrypt folder trees (per-file, concurrent) |
| `pack` / `unpack` | Pack a whole folder into one encrypted streaming archive and restore it |
| `encrypt-text` / `decrypt-text` | Encrypt and decrypt UTF-8 text |
| `encrypt-media` / `decrypt-media` | Encrypt and decrypt media or PDFs |
| `inspect` | Describe any `.pqf`/`.pqfs`/key/signature file without decrypting |
| `sign` / `verify` | Sign and verify documents, text, media, and artifacts |
| `hybrid-sign` / `hybrid-verify` | ML-DSA + Ed25519/ECDSA-P256 dual signatures (`--digest` for GB-scale) |
| `ecdsa-sign` / `ecdsa-verify` | Standalone ECDSA-P256 signatures (RFC 6979, low-S) |

`pqforge` with no arguments prints a banner and grouped command help; every
command has `--help` with worked examples. Read the complete command guide at
[doc/CLI.md](doc/CLI.md).

### Shared encrypt-side flags

The bulk encrypt commands (`encrypt`, `encrypt-folder`, `encrypt-media`,
`pack`, and where applicable `encrypt-text`) share a small set of flags. The
matching decrypt commands need none of them — every choice is recorded in the
self-describing container and auto-detected on read:

| Flag | Effect |
| --- | --- |
| `--hybrid` | Add an X25519 leg (finds `<key-id>.x25519.public.json` next to `--recipient-public`); confidentiality holds while ML-KEM **or** X25519 stands |
| `--recipient-public` (repeatable) | Encrypt once, key-wrap to several recipients (first = primary) |
| `--cipher chacha20-poly1305` | Use ChaCha20-Poly1305 instead of AES-256-GCM (~2.6× faster in pure Dart, ideal without hardware AES) |
| `--engine cryptography\|pure-dart` | Pick the AEAD backend (`cryptography` is the fast default; `pure-dart` is the PointyCastle reference) |
| `--profile` / `--kem` / `--sig` | Composition strength; `--kem`/`--sig` decouple KEM and signature levels |
| `--signer-secret` | Sign the envelope/header with an ML-DSA key (O(1) in file size) |

### Large files and bounded memory

Inputs at or above 8 MiB automatically use the `.pqfs` streaming container: a
signed master header followed by independently authenticated frames, with a
working set of roughly two frames regardless of total size. The library
surface is `package:pqforge/pqforge_io.dart`:

```dart
import 'package:pqforge/pqforge_io.dart';

final cipher = PqForgeStreamCipher(); // fast cryptography engine by default
await cipher.encryptFile(
  recipientPublicKey: recipientKemPublicKey,
  recipientKexPublicKey: recipientX25519PublicKey, // optional: hybrid
  input: File('movie.mp4'),
  output: File('movie.mp4.pqf'),
  profile: PqForgeProfile.maximum,
);

// Off the UI isolate on Flutter:
await PqForgeStreamCipher.encryptFileInBackground(
  recipientPublicKey: recipientKemPublicKey,
  inputPath: 'movie.mp4',
  outputPath: 'movie.mp4.pqf',
  profile: PqForgeProfile.maximum,
);
```

### Hybrid and classical signers — in the CLI

`keygen` emits every classical keypair by default, and the hybrid and
standalone classical signers are wired into matching commands:

| Capability | CLI | Library API | Powered by |
| --- | --- | --- | --- |
| Hybrid encryption (PQC + X25519) | `encrypt --hybrid` (and every bulk command) | `encryptAsync(recipientKexPublicKey:)`, `PqHybridKemDem` | 🤝 X25519 + 🛡️ ML-KEM → 🔒 AEAD |
| Hybrid signatures (PQC + Ed25519/ECDSA-P256) | `hybrid-sign` / `hybrid-verify` | `PqForgeHybridSigner()` | 🛡️ ML-DSA + (🤝 Ed25519 \| 🔒 ECDSA-P256) |
| Standalone ECDSA-P256 sign/verify | `ecdsa-sign` / `ecdsa-verify` | `PqEcdsaP256` | 🔒 ECDSA-P256 (RFC 6979, low-S) |
| Classical signer keypair (Ed25519 / ECDSA-P256) | `keygen` (or `--classical ed25519\|ecdsa-p256`) | `PqForgeHybridSigner.generateClassicalKeyPair()` | 🤝 Ed25519 · 🔒 ECDSA-P256 |
| X25519 key-agreement keypair | `keygen` (or `--classical x25519`) | `PqForgeHybridKeyAgreement.generateClassicalKeyPair()` | 🤝 X25519 |

Two primitives stay library-only **by design** — they can't be expressed as a
one-shot CLI command:

| Capability | Library API | Why library-only |
| --- | --- | --- |
| App-supplied dual signatures | `dualSign` / `dualVerify` | `dualVerify` takes a classical-verifier **callback**, so a bring-your-own scheme can't be passed on a command line. Use `hybrid-sign` for the built-in Ed25519/ECDSA-P256 schemes. |
| Hybrid session derivation (raw bytes) | `PqForgeCombiner`, `SecretKey.deriveHybridSecretKey()` | Interactive, multi-party key agreement; the raw classical ‖ ML-KEM join is a building block, not a workflow. |

## Profiles

| Profile | KEM | Signature | Best for |
| --- | --- | --- | --- |
| `compact` | ML-KEM-512 | ML-DSA-44 | smaller demos and constrained payloads |
| `balanced` | ML-KEM-768 | ML-DSA-65 | default application and server workflows |
| `maximum` | ML-KEM-1024 | ML-DSA-87 | long-lived records, archives, media, and high-value artifacts |

## Hybrid Sessions

The single `package:pqforge/pqforge.dart` import also provides:

- `PqForgeHybridKeyAgreement` for X25519 + ML-KEM session key agreement;
- `PqForgeHybridSigner` for ML-DSA + Ed25519 **or ECDSA-P256** dual signatures;
- `PqForgeSecureSession` for AES-256-GCM or ChaCha20-Poly1305 packets;
- `SecretKey.deriveHybridSecretKey()` for `package:cryptography` users.

ECDSA over NIST P-256 is built in via `PqEcdsaP256` (pure-Dart PointyCastle, with
RFC 6979 deterministic nonces and low-S signatures), because `cryptography 2.9.0`
cannot generate P-256 keys on the Dart VM. `dualSign` / `dualVerify` remain for
any other app-supplied classical signature scheme.

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
