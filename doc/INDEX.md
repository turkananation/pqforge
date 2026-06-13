# pqforge Documentation Index

This is the canonical documentation map for `pqforge`. Use `doc/` links for
project documentation, [`site/`](../site/) for the generated GitHub Pages
surface, and [`wiki/`](../wiki/) for the GitHub Wiki source.

> `pqforge` is the **application layer** built on
> [`pqcrypto`](https://pub.dev/packages/pqcrypto) (FIPS 203 ML-KEM, FIPS 204
> ML-DSA). `pqcrypto` is the primitives; `pqforge` is the envelopes, hybrids,
> streaming, key custody, recipes, and CLI. See
> [HYBRID_AUDIT.md](HYBRID_AUDIT.md) for the full boundary.

## Start Here

| Need | Document |
| --- | --- |
| Package overview and selling points | [../README.md](../README.md) |
| Full CLI usage | [CLI.md](CLI.md) |
| API reference | [API.md](API.md) |
| App and project catalog | [cookbook/PROJECT_CATALOG.md](cookbook/PROJECT_CATALOG.md) |
| Recipe cookbook | [cookbook/README.md](cookbook/README.md) |
| Hybrid coverage audit (vs `pqcrypto`) | [HYBRID_AUDIT.md](HYBRID_AUDIT.md) |
| Performance, memory, and engine choice | [technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md](technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md) |
| Container formats (`.pqf` / `.pqfs`) | [architecture/ENVELOPE_FORMATS.md](architecture/ENVELOPE_FORMATS.md) |
| Key custody | [architecture/KEY_CUSTODY.md](architecture/KEY_CUSTODY.md) |
| Threat model | [security/THREAT_MODEL.md](security/THREAT_MODEL.md) |
| Claim boundary | [security/CLAIM_BOUNDARY.md](security/CLAIM_BOUNDARY.md) |
| GitHub Pages and AI discovery generation | [../tool/visibility/README.md](../tool/visibility/README.md) |

## Full Documentation Map

### Reference

| Document | Covers |
| --- | --- |
| [API.md](API.md) | Facade, hybrid KEM combining, hybrid key agreement, dual signatures, AEAD sessions, engines, supporting types |
| [CLI.md](CLI.md) | Every command and flag: keys, files, folders, text, media, streaming, pack, multi-recipient, hybrid, signing, inspect |
| [HYBRID_AUDIT.md](HYBRID_AUDIT.md) | What `pqforge` composes on top of `pqcrypto`, and the explicit rejections (RC4, AES-as-signature) |

### Cookbook

| Document | Covers |
| --- | --- |
| [cookbook/README.md](cookbook/README.md) | Recipe index and the provide/supply/caveat rule |
| [cookbook/PROJECT_CATALOG.md](cookbook/PROJECT_CATALOG.md) | Applications and domains mapped to recipes |
| [cookbook/FILE_ENCRYPTION.md](cookbook/FILE_ENCRYPTION.md) | File and folder encryption |
| [cookbook/TEXT_MEDIA_AND_FOLDERS.md](cookbook/TEXT_MEDIA_AND_FOLDERS.md) | Text, media, and folder recipe APIs |
| [cookbook/DOCUMENT_SIGNING.md](cookbook/DOCUMENT_SIGNING.md) | Document signing |
| [cookbook/WEBHOOKS_AND_TOKENS.md](cookbook/WEBHOOKS_AND_TOKENS.md) | Webhook integrity and signed tokens |
| [cookbook/GOVERNMENT_RECORDS.md](cookbook/GOVERNMENT_RECORDS.md) | Public-sector records |
| [cookbook/MEDICAL_RECORDS.md](cookbook/MEDICAL_RECORDS.md) | Patient records |

### Architecture

| Document | Covers |
| --- | --- |
| [architecture/ENVELOPE_FORMATS.md](architecture/ENVELOPE_FORMATS.md) | `.pqf` one-shot and `.pqfs` streaming layouts, AAD binding, reserved markers |
| [architecture/KEY_CUSTODY.md](architecture/KEY_CUSTODY.md) | Wrapped-key model and pluggable custody stores |
| [architecture/SEPARATION_OF_CONCERNS.md](architecture/SEPARATION_OF_CONCERNS.md) | Layering: algorithms, codecs, services, CLI |

### Security

| Document | Covers |
| --- | --- |
| [security/THREAT_MODEL.md](security/THREAT_MODEL.md) | Assets, adversaries, defended properties, application responsibilities |
| [security/CLAIM_BOUNDARY.md](security/CLAIM_BOUNDARY.md) | Allowed and forbidden claims |
| [security/KEY_MANAGEMENT.md](security/KEY_MANAGEMENT.md) | Key lifecycle, rotation, and storage guidance |

### Technical

| Document | Covers |
| --- | --- |
| [technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md](technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md) | As-built throughput/memory, engine and cipher recommendations, measured numbers |
| [technical/PERFORMANCE_OPTIMIZATIONS.md](technical/PERFORMANCE_OPTIMIZATIONS.md) | Optimization changelog and rationale |
| [technical/PQFORGE_TECHNICAL_BLUEPRINT.md](technical/PQFORGE_TECHNICAL_BLUEPRINT.md) | System blueprint and design intent |
| [technical/PQFORGE_OPTIMIZATION_BLUEPRINT.md](technical/PQFORGE_OPTIMIZATION_BLUEPRINT.md) | Phased optimization plan and defect backlog |
| [technical/PHASE0_BENCHMARK_BASELINE.md](technical/PHASE0_BENCHMARK_BASELINE.md) | Baseline benchmark methodology |
| [technical/PHASE7_NATIVE_LATTICE_FFI.md](technical/PHASE7_NATIVE_LATTICE_FFI.md) | Why the published package stays FFI-free (dev-tool interop only) |
| [technical/SCOPE_AUDIT_AND_LIMITS.md](technical/SCOPE_AUDIT_AND_LIMITS.md) | Scope, limits, and non-goals |

### Decisions and Roadmap

| Document | Covers |
| --- | --- |
| [decisions/ADR-0001-core-package-boundary.md](decisions/ADR-0001-core-package-boundary.md) | Pure-Dart, web-safe core boundary |
| [decisions/ADR-0002-optional-classical-hybrid-tier.md](decisions/ADR-0002-optional-classical-hybrid-tier.md) | Optional classical hybrid tier |
| [roadmap/ROADMAP.md](roadmap/ROADMAP.md) | Direction and themes |
| [roadmap/MILESTONES.md](roadmap/MILESTONES.md) | Milestone definitions |
| [roadmap/PROJECT_TRACKER.md](roadmap/PROJECT_TRACKER.md) | Status tracker |

### CI and Release

| Document | Covers |
| --- | --- |
| [ci/CI_PLAN.md](ci/CI_PLAN.md) | CI jobs: visibility check, format, analyze, test, examples, CLI smoke, OpenSSL interop, memory gate |
| [ci/RELEASE_CHECKLIST.md](ci/RELEASE_CHECKLIST.md) | Pre-publish checklist and the `v*` tag binary release flow |

## Package Surface

| Area | Coverage |
| --- | --- |
| PQC primitives | ML-KEM-512/768/1024 and ML-DSA-44/65/87 through `pqcrypto` |
| Encryption | KEM-DEM envelopes; AES-256-GCM and ChaCha20-Poly1305 AEAD; one-shot `.pqf` and streaming `.pqfs` |
| Large files | Auto-streaming at ≥ 8 MiB (bounded memory); `pack`/`unpack` whole-folder archives |
| Multi-recipient | One sealed payload, DEM key wrapped per recipient, no wire-format change |
| Engines | `cryptography` (fast default, hardware-backed on Flutter) and `pure-dart` (PointyCastle), interoperable |
| Sessions | AES-256-GCM and ChaCha20-Poly1305 packet sessions |
| Hybrid transition | X25519 + ML-KEM agreement; ML-DSA + Ed25519/ECDSA-P256 signatures; standalone ECDSA-P256 |
| Key custody | Argon2id + AES-GCM wrapped keys (PBKDF2 under FIPS mode) and pluggable stores |
| CLI | file, folder, text, media, streaming, pack, multi-recipient, signing, verification, inspect, wrapped key reuse |
| Recipes | documents, text, media, email, webhooks, tokens, records, logs, artifacts, identity bindings |

## Generated Visibility

The generated visibility files (`llms.txt`, `llms-full.txt`, `identity.json`,
`faq-ai.txt`, the `site/` static pages, and the editor/agent rule files) are
controlled by
[`tool/visibility/visibility_manifest.json`](../tool/visibility/visibility_manifest.json).
**Do not edit the generated files directly.** Edit the manifest, then run:

```bash
dart run tool/visibility/generate_visibility.dart
dart run tool/visibility/generate_visibility.dart --check
```

The generated root files are copied into `site/` so GitHub Pages and AI
discovery surfaces stay consistent. The cross-repository documentation contract
is described in the
[`pqforge-docs` skill](../.claude/skills/pqforge-docs/SKILL.md) and
[CLAUDE.md](../CLAUDE.md).
