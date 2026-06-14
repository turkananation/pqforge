# pqforge Agent Guide

This is the canonical Codex entrypoint for `pqforge`. Keep it concise: use the
workflow skills and repository scripts for detail instead of rediscovering the
same commands in every task.

## Ground Truth

Read only what the task needs, in this order:

1. `pubspec.yaml` for the current version, SDK, and dependencies.
2. `CHANGELOG.md` for released behavior.
3. `CLAUDE.md` for package boundaries and the repository map.
4. The source and tests for the area being changed.
5. `doc/INDEX.md` when documentation or architecture context is needed.

Do not trust a roadmap, changelog entry, generated page, or old agent response
without checking the live source.

## Hard Constraints

- Keep `package:pqforge/pqforge.dart` pure Dart and web-safe. Do not introduce
  `dart:io` or `dart:ffi` into its transitive import graph.
- Put filesystem functionality behind `package:pqforge/pqforge_io.dart`.
- The only sanctioned FFI code is the unpublished
  `tool/openssl_interop/` package.
- `pqforge` composes `pqcrypto`; it does not reimplement ML-KEM or ML-DSA.
- Use authenticated encryption, explicit AAD, and domain-separated recipe
  framing. Do not add RC4 or unauthenticated encryption.
- Never claim FIPS/CMVP validation, certification, hard constant-time Dart
  behavior, or hard memory erasure. Read `doc/security/CLAIM_BOUNDARY.md`.
- Preserve wire compatibility unless the task explicitly introduces a
  versioned format migration.
- Never discard unrelated user changes from a dirty worktree.

## Change Routing

Use the smallest workflow that covers the task:

- `$pqforge-feature`: library, CLI, format, crypto-composition, or test changes.
- `$pqforge-docs`: README, changelog, `doc/`, `wiki/`, visibility manifest, or
  generated discovery/site files.
- `$pqforge-release`: versioning, release notes, package contents, tags, or
  pub.dev preparation.

Repository skills live under `.codex/skills/`. Claude Code adapters live under
`.claude/skills/`.

## Generated Files

Do not hand-edit these:

- `bin/src/version.g.dart`: generated from `pubspec.yaml` by
  `tool/version/generate_version.dart`.
- `llms.txt`, `llms-full.txt`, `identity.json`, `developer-ai.txt`,
  `faq-ai.txt`, `ai.txt`, `robots*.txt`, `.github/copilot-instructions.md`,
  `.github/instructions/**`, `.cursor/rules/**`, `.windsurfrules`, and
  `site/**`: generated from `tool/visibility/visibility_manifest.json`.

Run the matching generator, then its `--check` mode.

## Current Documentation

Whenever a task asks about a library, framework, SDK, API, CLI tool, or cloud
service, use Context7 before answering or coding:

```bash
npx ctx7@latest library "<Official Name>" "<full user question>"
npx ctx7@latest docs <library-id> "<specific question>"
```

Resolve the library first unless the user supplied `/org/project`. Prefer an
exact official match, high source reputation, and the relevant version. Use no
more than three Context7 commands per question. Do not send secrets. On quota
errors, report `npx ctx7@latest login` or `CONTEXT7_API_KEY`; on DNS/network
errors, retry outside the sandbox.

Do not use Context7 for local business logic, refactoring, scripts written from
scratch, or code review.

## MCP

Project-local MCP configuration is committed for:

- Context7: current external documentation.
- Dart SDK MCP: analysis, tests, package inspection, and language tooling.

Codex reads `.codex/config.toml`; Claude Code reads `.mcp.json`. Keep secrets and
machine-specific paths out of both files. GitHub or other authenticated MCP
servers belong in user-level configuration.

## Validation

Use the repository runner:

```bash
dart run tool/agent/verify.dart quick    # generators, boundaries, format, analyze
dart run tool/agent/verify.dart docs     # generators and documentation links
dart run tool/agent/verify.dart full     # quick + links + tests + examples
dart run tool/agent/verify.dart release  # full + strict pub archive validation
```

Also run focused tests from `$pqforge-feature` while iterating. Run the
OpenSSL interop harness or streaming memory gate when those areas change.

## Publication Boundary

The pub.dev archive should contain the consumable package only: `lib/`, `bin/`,
`example/`, `pubspec.yaml`, `README.md`, `CHANGELOG.md`, and `LICENSE`.
Repository automation, agent files, tests, internal docs, generated discovery
surfaces, and development tools are excluded by `.pubignore`.

Validate the boundary with:

```bash
dart run tool/agent/check_publish_surface.dart
```
