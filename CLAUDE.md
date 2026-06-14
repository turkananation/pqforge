# CLAUDE.md

Guidance for Claude Code and other AI agents working in this repository.
Codex uses [AGENTS.md](AGENTS.md) as its concise entrypoint; both tools share
the workflows under `.codex/skills/` and `.claude/skills/`.

## What pqforge is

`pqforge` is a **pure-Dart, web-safe post-quantum application toolkit**. It is the
*composition layer* built on [`pqcrypto`](https://pub.dev/packages/pqcrypto)
(FIPS 203 ML-KEM, FIPS 204 ML-DSA): KEM-DEM envelopes, AES-256-GCM /
ChaCha20-Poly1305 AEAD, X25519/Ed25519/ECDSA-P256 hybrids, bounded-memory
streaming, multi-recipient envelopes, Argon2id key custody, named recipes, and a
CLI. `pqforge` depends on `pqcrypto` and **never reimplements the lattice
primitives**. See [doc/HYBRID_AUDIT.md](doc/HYBRID_AUDIT.md) and the
[pqforge vs pqcrypto](https://github.com/turkananation/pqforge/wiki/pqforge-vs-pqcrypto)
wiki page.

## Hard constraints (do not violate)

1. **Pure Dart, no `dart:ffi` in the published package.** The core
   (`package:pqforge/pqforge.dart`) must stay web-safe — runnable on the Dart VM,
   Flutter, and the web. `dart:io` code lives **only** behind
   `package:pqforge/pqforge_io.dart`. The single sanctioned FFI exception is the
   nested, `publish_to: none` dev tool `tool/openssl_interop/` (excluded from the
   package via `.pubignore`).
2. **Respect the claim boundary.** Never claim "FIPS validated", "CMVP
   validated", "certified", hard constant-time Dart behavior, or hard memory
   erasure. Never add RC4 or unauthenticated encryption. AES encrypts; it never
   signs. See [doc/security/CLAIM_BOUNDARY.md](doc/security/CLAIM_BOUNDARY.md).
3. **Authenticated encryption only**, with explicit domain separation / AAD
   binding on every recipe.

## Layout

| Path | Contents |
| --- | --- |
| `lib/pqforge.dart` | Web-safe core umbrella (single public import) |
| `lib/pqforge_io.dart` | `dart:io` streaming/pack entrypoint (re-exports the core) |
| `lib/src/algorithms/` | ML-KEM/ML-DSA wrappers, FIPS mode, swappable lattice provider |
| `lib/src/cipher/` | AEAD engines (PointyCastle + `cryptography`), cipher suites, secure session |
| `lib/src/codecs/` | `.pqf` envelope and `.pqfs` streaming envelope codecs |
| `lib/src/hybrid/` | Combiner, `cryptography` extensions, ECDSA-P256, hybrid signer/agreement |
| `lib/src/keys/` | Key bundles, custody, wrapping |
| `lib/src/recipes/` | Domain-separated recipe message framing |
| `lib/src/services/` | Facade services: one-shot, async, stream, pack, multi-recipient |
| `bin/`, `bin/src/` | CLI entrypoint and command groups |
| `doc/` | Canonical project docs (see [doc/INDEX.md](doc/INDEX.md)) |
| `wiki/` | GitHub Wiki source, synced by `.github/workflows/sync-wiki.yml` |
| `site/` | **Generated** GitHub Pages site (do not hand-edit) |
| `tool/visibility/` | Visibility generator + manifest (single source for AI-discovery files) |
| `tool/agent/` | Deterministic link, publication, and verification workflows |
| `tool/openssl_interop/` | Dev-only OpenSSL AEAD interop harness (`publish_to: none`) |
| `example/` | Runnable examples exercised in CI |
| `test/` | Tests, including the streaming peak-RSS memory gate |

## Documentation system (read before touching docs)

Two kinds of docs exist, and they are edited differently:

- **Hand-maintained:** `README.md`, `CHANGELOG.md`, everything under `doc/`, and
  everything under `wiki/`. Edit directly. Keep claims aligned to code.
- **Generated — never hand-edit:** `llms.txt`, `llms-full.txt`, `identity.json`,
  `faq-ai.txt`, `developer-ai.txt`, `ai.txt`, `robots.txt`, `robots-ai.txt`,
  `.github/copilot-instructions.md`, `.github/instructions/**`,
  `.cursor/rules/**`, `.windsurfrules`, and the entire `site/` tree (except the
  committed binary `site/assets/`). These are produced from
  **`tool/visibility/visibility_manifest.json`** by
  `tool/visibility/generate_visibility.dart`. To change them, edit the manifest
  (or the generator), then regenerate:

  ```bash
  dart run tool/visibility/generate_visibility.dart
  dart run tool/visibility/generate_visibility.dart --check
  ```

  CI (`.github/workflows/ci.yml`, `visibility.yml`) fails if the generated files
  are out of sync with the manifest.

**Repository links in generated files** are built from
`project.repository_branch` in the manifest — keep it `main` so published links
never point at a feature branch.

For the full, step-by-step documentation procedure (verification protocol,
no-hallucination rules, the regenerate-and-link checklist), use the
[`pqforge-docs` skill](.claude/skills/pqforge-docs/SKILL.md).

For implementation and release work, use
[`pqforge-feature`](.claude/skills/pqforge-feature/SKILL.md) and
[`pqforge-release`](.claude/skills/pqforge-release/SKILL.md).

## Validation (run before claiming done)

```bash
dart run tool/agent/verify.dart quick
dart run tool/agent/verify.dart full
dart run tool/agent/verify.dart release  # clean release checkout
```

The OpenSSL interop tool has its own resolution: `dart pub get --directory
tool/openssl_interop`. Branch model: work on a feature branch off `main`;
`main` and `develop` trigger the Pages and Wiki sync workflows.

## Pointers

- Docs map: [doc/INDEX.md](doc/INDEX.md)
- API reference: [doc/API.md](doc/API.md)
- CLI reference: [doc/CLI.md](doc/CLI.md)
- Performance facts (measured): [doc/technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md](doc/technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md)
- Visibility generator: [tool/visibility/README.md](tool/visibility/README.md)
- Agent verification runner: [tool/agent/verify.dart](tool/agent/verify.dart)
