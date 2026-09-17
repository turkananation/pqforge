# Changelog

## 0.4.5

Sync ChaCha20-Poly1305 is dart2js-safe. No `.pqf` / `.pqfs` /
`PqForgeSecureSession` wire-format changes.

- **`PqSymmetricPrimitives.chacha20Poly1305Encrypt` / `Decrypt`** now use
  `package:cryptography`'s Dart engine (`DartChacha20.poly1305Aead`, 32-bit
  Poly1305) instead of PointyCastle `Poly1305()`. Wire layout is unchanged:
  32-byte key, caller-supplied 12-byte nonce, `ciphertext || tag`. RFC 8439
  §2.8.2 still holds. dart2js can run the helper; PointyCastle cannot
  (IEEE-754 mantissa, `2^53 + 1 == 2^53`).
- **`PqSymmetricPrimitives.supportsChaCha20Poly1305`** — always `true`.
  Callers must not copy PointyCastle's full-width-integer check. The
  PointyCastle **session** engine (`PqForgePointyCastleAeadEngine` ChaCha)
  still needs 64-bit integers; use this helper or
  `PqForgeEngineProvider.nativeCryptography` on dart2js.
- Chrome CI runs the sync ChaCha group under dart2js (RFC vector, round-trip,
  bit-flip, capability). Tests are not skipped.
- **pub.dev score** — `pubspec.yaml` description is 60–180 characters.
  `LICENSE` is SPDX MIT (`TORT`, not `TITLE`; no duplicated "to persons").
  `NOTICE` matches MIT (stale AGPL dual-license text removed).
- **`pqcrypto: ^0.4.2`.** That version ships `doc/cookbook/README.md` in
  the pub.dev archive, so `dart doc` no longer crashes while initializing
  pqcrypto's Cookbook category. Required for pqforge's own documentation
  points.

## 0.4.4

Additive library surface, CLI progress across file operations, and first-class
SLH-DSA keygen/sign/verify. No `.pqf` / `.pqfs` / `PqForgeSecureSession`
wire-format changes.

### Library (pqtransport uplink)

- **`PqBytes.sha512`**, **`PqBytes.sha512OfStream`**, and **`PqBytes.hmacSha512`** — SHA-512 helpers for protocols (e.g. FROST-Ed25519) that need a 512-bit digest facade alongside the existing SHA-256 APIs. Additive only; no wire-format changes.
- **NIST-curve ECDH** — `PqNistEcdh` plus `PqClassicalProvider.p256*` / `p384*` and `PqForgeHybridKeyAgreement.p256SharedSecret` / `p384SharedSecret`. Uncompressed SEC1 (`0x04 || X || Y`); shared secret is the x-coordinate (RFC 8446 / SP 800-56A). Full public-key validation: rejects infinity, all-zero x, missing `0x04`, off-curve points, and out-of-range scalars. Does **not** overload `PqEcdsaP256` (signatures only). Unlocks TLS hybrid groups SecP256r1MLKEM768 / SecP384r1MLKEM1024 for `pqtransport`. Additive; no `.pqf`/`.pqfs` changes. Custom `PqClassicalProvider` implementors must add the four ECDH methods.
- **RFC 5869 HKDF-Extract / Expand** — `PqSymmetricPrimitives.hkdfExtractSha256` / `hkdfExpandSha256` / `hkdfExtractSha384` / `hkdfExpandSha384`, plus `PqBytes.sha384` / `hmacSha384` / `sha384OfStream` and combined `hkdfSha384`. Existing `hkdfSha256` is unchanged. Expand-Label stays in the protocol layer.
- **Sync ChaCha20-Poly1305** — `PqSymmetricPrimitives.chacha20Poly1305Encrypt` / `Decrypt` matching the AES-GCM helper shape (32-byte key, caller-supplied 12-byte nonce, `ciphertext || tag`). Distinct from `PqForgeSecureSession.encrypt` (async, self-nonce, nonce-prepended packet).
- **Concat-only hybrid join** — `PqForgeCombiner.concatenateSharedSecrets` with `PqHybridConcatOrder`. Does not HKDF. `combine()` still always does `classical || PQ` then HKDF. RFC 10024 X25519MLKEM768 must use `pqThenClassical` and must **not** call `combine()`.
- **`PqKemPrimitives.checkEncapsulationKey`** — FIPS 203 §7.2 modulus check as a `bool` before encapsulate (length + pqcrypto validation). Does not reimplement ML-KEM.

### SLH-DSA (FIPS 205) — keygen, custody, and detached sign/verify

`pqforge` composes all 12 FIPS 205 parameter sets from `pqcrypto` into
application key material:

- **`PqSlhDsaAlgorithm`** — SHA-2 and SHAKE × 128s/128f/192s/192f/256s/256f,
  with sizes matching `SlhDsaParams`.
- **`PqSlhDsaPrimitives`** and **`PqForge.generateSlhDsaKeyPair`** /
  **`signSlhDsa`** / **`verifySlhDsa`**. Recipe helpers (`signDocument`,
  `signText`, `signMedia`, `signWebhook`, `signArtifact` and their verify
  twins) accept an optional `slhDsa:` parameter. Slow `s` sets still require
  `allowSlowSigning` at the primitive layer, matching `pqcrypto`.
  `issueToken`, signed logs, and identity bindings stay ML-DSA because they
  serialize `PqSignatureAlgorithm`.
- **`keygen`** emits a profile-matched SHAKE-f key by default (`compact` →
  SLH-DSA-SHAKE-128f, `balanced` → 192f, `maximum` → 256f) as
  `<key-id>.slh-dsa-shake-<n>f.{public,secret}.json`, next to the ML-KEM/ML-DSA
  bundle and classical keys. `--slh-dsa` selects specific sets, `--no-slh-dsa`
  skips them, `--slh-dsa-only` emits only SLH-DSA. Secrets wrap through the
  same Argon2id + AES-256-GCM path as ML-DSA.
- **`sign` / `verify`** accept SLH-DSA keys (same `signature-public` /
  `signature-secret` kinds, distinguished by `algorithmId`).

**Still ML-DSA-only:** envelope headers, `.pqfs` streaming signatures, and
`hybrid-sign` / `hybrid-verify`. SLH-DSA signatures are 8–50 KiB and the `s`
sets are slow; those workflows stay compact ML-DSA. Passing an SLH-DSA key as
`--signer-secret` on encrypt/hybrid-sign is rejected with a clear error.

`SlhDsa` / `SlhDsaParams` / `SlhDsaPreHash` remain re-exported from `pqcrypto`.

### CLI

- **Progress** — `encrypt`, `decrypt`, `encrypt-text`, `decrypt-text` (when `--out` is set), `encrypt-media`, `decrypt-media`, `encrypt-folder`, `decrypt-folder`, `pack`, `unpack`, `sign`, `verify`, `hybrid-sign`, `hybrid-verify`, `ecdsa-sign`, and `ecdsa-verify` print a live, throttled progress line. Folder jobs forward streaming byte progress from background isolates over a `SendPort` (callbacks are not isolate-sendable); concurrent files keep separate live totals and the CR line aggregates them. Pack/unpack report per-entry and in-entry bytes. `--digest` hybrid/ECDSA signing reports hashing progress. `keygen` reports per-key wrapping progress when a passphrase is used. A folder job that fails any file exits non-zero. Pack/unpack failures before the first entry report a job-level failure instead of a success summary. Throughput is measured from finished bytes, not started ones.
- **`--quiet` / `-q`** — mutes line-by-line file summaries and skip warnings. Honored on the progress commands and on `keygen`. The completion summary still prints. `keygen --quiet` still prints the raw-secret warning. `decrypt-text` without `--out` never attaches a progress line, so piped plaintext stays clean.
- **Skippable entries** — folder listing skips sockets, FIFOs, broken
  symlinks, and unreadable files (warns unless `--quiet`) instead of failing
  the whole tree.

### What 0.4.4 enables

- `pqtransport` TLS 1.3 hybrid groups (SecP256r1MLKEM768, SecP384r1MLKEM1024, RFC 10024 X25519MLKEM768) without reimplementing ECDH, HKDF-Extract/Expand, sync ChaCha20-Poly1305, concat combiners, or ML-KEM encapsulation-key checks.
- Protocol facades (SHA-384/SHA-512, HMAC-SHA-384/512) for TLS, QUIC, and FROST-style constructions.
- SLH-DSA key generation, custody, and detached signatures through the same CLI and facade as ML-DSA.
- Live progress on encrypt/decrypt/text/media/folder/pack/unpack/sign/verify/hybrid-sign/ecdsa-sign, including isolate-forwarded byte progress on folder jobs and wrapping progress on `keygen`.

### CI

- **pub.dev** — `.github/workflows/publish.yml` publishes the package on `vX.Y.Z` tags using GitHub Actions OIDC (no long-lived pub token). Enable it once on the [package admin page](https://pub.dev/packages/pqforge/admin): repository `turkananation/pqforge`, tag pattern `v{{version}}`, GitHub Actions environment name `pub.dev` (not the workflow filename). The job uses `environment: pub.dev`. The existing `release.yml` still attaches AOT CLI binaries on the same tags.

## 0.4.3

Update pqcrypto to `^0.4.1`. That version ships FIPS 205 SLH-DSA (all 12 parameter sets). pqforge re-exports them through `package:pqcrypto/pqcrypto.dart` but does not compose them into `keygen`, envelopes, recipes, or `hybrid-sign`. No cryptographic or wire-format changes; existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

## 0.4.2

Minor fixes and documentation: Exported more files from the library for external use. No cryptographic or wire-format changes; existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

## 0.4.1

Minor fixes and documentation. No cryptographic or wire-format changes; existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

## 0.4.0

Prepare to land SLH-DSA from pqcrypto into pqforge. No cryptographic or wire-format changes; existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

## 0.3.0

Swappable **classical** backend — the hardware-acceleration seam for the hybrid
stack. Additive and backward-compatible: the default stays pure-Dart and all
`.pqf`/`.pqfs` containers and wire formats are unchanged.

- New `PqClassicalProvider` seam (the classical counterpart to
  `PqLatticeProvider`): X25519 key agreement, Ed25519 and ECDSA-P256 signatures.
  Register a native backend once at startup via `PqClassical.provider = ...`; the
  default is `PqPureDartClassicalProvider` (`package:cryptography` + PointyCastle).
- The **entire** classical half of the hybrid stack now delegates to
  `PqClassical.provider`: `PqForgeHybridSigner`, the static
  `PqForgeHybridKeyAgreement.x25519SharedSecret`, **and** the live-keypair
  `PqForgeHybridKeyAgreement.generateClassicalKeyPair`/`initiate`/`accept`
  handshake (X25519 keygen + both ECDH sides). A host (e.g. an FFI binding to
  AWS-LC) can therefore hardware-accelerate the full hybrid handshake — matching
  the existing lattice seam. Behaviour is unchanged on the default provider
  (same `package:cryptography` under the seam), and because X25519 ECDH is
  deterministic a native backend agrees byte-for-byte.
- New conformance/agreement harness `test/support/classical_conformance.dart`:
  X25519 ECDH and Ed25519 (RFC 8032) must be byte-identical across backends;
  ECDSA-P256 is cross-verified, since its signatures are implementation-dependent
  (pqforge uses RFC-6979; a native backend may be randomized).

## 0.2.2

CLI lifecycle and developer tooling. No cryptographic or wire-format changes;
existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

- The CLI version is single-sourced from `pubspec.yaml`. `bin/src/version.g.dart`
  is generated by `tool/version/generate_version.dart` and powers `pqforge
  --version`, the new `pqforge version` subcommand, and the banner. A `--check`
  mode and a unit test fail if it drifts. The visibility/site version is read
  from `pubspec.yaml` too, so the manifest no longer carries a version.
- New `pqforge uninstall` command removes pqforge however it was installed: it
  runs `dart pub global deactivate pqforge` for a global pub install (with
  `--dry-run` and `--yes`), or prints the executable path to delete for a
  standalone binary. It never blocks for input in non-interactive shells.
- Added a repeatable local/CI verification runner, `tool/agent/verify.dart`
  (`quick`/`docs`/`full`/`release`), with package-boundary, Markdown-link, and
  pub.dev archive checks. `.pubignore` now limits the published archive to the
  runtime package (`lib/`, `bin/`, `example/`, and metadata).
- Docs: README and the CLI guide cover pub.dev install, `pqforge uninstall`, and
  `pqforge version`.

## 0.2.1

Documentation, discovery, and site release. No library or CLI behavior changes
— only the version string moves (`pubspec.yaml`, `pqforgeCliVersion`).

- Docs realigned to the as-shipped v0.2.0 surface: the CLI guide now covers
  auto-streaming (`.pqfs` at ≥ 8 MiB), `pack`/`unpack`, multi-recipient and
  hybrid encryption, `--cipher`/`--engine`, digest signing, and `inspect`, and a
  stale "no multi-GB streaming" note was removed. `doc/INDEX.md` now maps every
  document, and the hybrid audit lists the full v0.2.0 command set.
- Fixed published links that pointed at a feature branch: generated discovery
  files and the site now build repository links from `main`, driven by
  `repository_branch` in the visibility manifest. Also repaired two dead
  doc links and removed a non-portable local path from the audit notes.
- Surfaced the `pqcrypto` relationship and differentiation: a new README section
  and `pqforge-vs-pqcrypto` wiki page, a "Relationship to pqcrypto" block in
  `llms.txt`/`llms-full.txt`, and `isBasedOn` structured data in `identity.json`.
- Expanded the LLM/AI discovery surface: `faq-ai.txt` grew from 5 to 21 Q&As,
  with richer capabilities, recipes, and keywords.
- Expanded the wiki (new Streaming, Multi-Recipient, Performance, and
  pqforge-vs-pqcrypto pages; refreshed Home, CLI, sidebar, and recipe catalog).
- GitHub Pages site: prominent pub.dev / Wiki / GitHub / pqcrypto links, inline
  SVG icons, hero badges, and SEO/discovery metadata (Open Graph, Twitter card,
  keywords, canonical, and a `FAQPage` JSON-LD block).
- Added `CLAUDE.md` and a `pqforge-docs` skill that keep documentation aligned
  to the code (verify-against-source, generated-vs-hand-maintained split, claim
  boundary, and the `main`-branch link rule).

## 0.2.0

Post-quantum + classical hybrid encryption, bounded-memory gigabyte-scale
streaming, multi-recipient envelopes, selectable AEAD suites, and a ~10×
faster default engine — all on the pure-Dart, web-safe core.

### Hybrid (ML-KEM + X25519) encryption

- End-to-end hybrid KEM-DEM: the DEM key is the IETF concatenate-then-KDF
  combination of the ML-KEM shared secret and an ephemeral X25519 exchange
  (`PqHybridKemDem`), so confidentiality holds while *either* Module-LWE or
  Curve25519 stands. The self-describing `hybridKex` metadata marker is
  KDF-bound (tampering flips the derived key, so the first AEAD tag check
  fails even on unsigned envelopes), needs no container-format change, and is
  shared verbatim by the one-shot and `.pqfs` streaming paths.
- `PqForge.encryptAsync`/`decryptAsync` — one-shot envelope encryption over any
  `PqForgeAeadEngine`, with optional hybrid keys; hybrid is auto-detected on
  decrypt. Output stays byte-compatible with the sync paths.
- CLI: `--hybrid` (or `--recipient-x25519-public`) on every encrypt command;
  decrypt auto-detects and finds the conventional
  `<key-id>.x25519.secret[.wrapped].json` next to `--recipient-secret`
  (override `--recipient-x25519-secret`).

### Multi-recipient envelopes

- Encrypt to N recipients with one ciphertext and **no wire-format change**:
  the payload is sealed exactly once and the DEM key is wrapped to each
  additional recipient as a `recipients[]` metadata entry (`PqMultiRecipient`,
  `PqRecipientSpec`; ~1.6 KB + ~2 ms per extra recipient instead of a full
  re-encryption). Entries may individually be hybrid (own ephemeral X25519),
  `recipientKeyId` routes openers straight to their entry, and the scheme works
  identically for one-shot envelopes and `.pqfs` streams. CLI:
  `--recipient-public` is repeatable on `encrypt`, `encrypt-folder`,
  `encrypt-text`, `encrypt-media`, and `pack` (first = primary).

### Selectable AEAD suite

- `--cipher chacha20-poly1305` on the encrypt commands. A non-default suite is
  recorded as a tamper-evident `aeadSuite` marker and every open path rebuilds
  its engine to match — no decrypt flag needed. Pure-Dart ChaCha measures
  ~30.4 MiB/s vs ~11.5 MiB/s AES-256-GCM (2.6×), the bulk recommendation
  wherever hardware AES is not dispatched; AES output stays marker-free and
  byte-compatible with prior releases. FIPS mode still rejects ChaCha.

### Performance & memory

- Bounded-memory streaming envelope (`.pqfs`) for gigabyte-scale files: a
  signed master header followed by independently authenticated frames (per-frame
  `seq`/`isFinal` AAD binding prevents truncation, reordering, duplication, and
  splicing). Peak memory is a small, file-size-independent working set.
- `package:cryptography` is the default AEAD engine for all bulk paths (~10×
  the PointyCastle throughput even in pure Dart; hardware-backed on Flutter via
  `FlutterCryptography.enable()`). `--engine cryptography|pure-dart` on every
  bulk command; wire formats are engine-independent. `encryptAsync`/
  `decryptAsync` extend the speedup to sub-8 MiB one-shot files, which
  previously ignored `--engine`.
- Streaming I/O is pipelined: `encryptFile` double-buffers (the next frame's
  read overlaps the current frame's seal+write) and `decryptStream` prefetches
  one frame; failure-cleanup semantics are unchanged.
- Envelope signatures are computed over `SHA-256(header ‖ SHA-256(payload))`
  with `preHash:true`, so signing cost and memory no longer scale with payload
  size.
- `keygen` wraps secret keys on a bounded isolate pool (`--wrap-concurrency`,
  default 2); folder commands process files concurrently via a bounded per-file
  isolate pool (`--concurrency`).
- `pqforge pack` / `pqforge unpack`: collapse a whole folder into one encrypted
  streaming archive (a single KEM encapsulation and signature for the tree) and
  restore it path-traversal-safe. Both stream end to end — no plaintext temp
  spool, no extra disk need — and a failed unpack removes everything it created.

### Signing

- Digest-mode signing: `hybrid-sign --digest` / `ecdsa-sign --digest` sign the
  streamed SHA-256 of the input (`PqBytes.sha256OfStream`, O(1) memory for
  gigabyte artifacts) under a domain-separation label, recorded in the
  signature JSON so the verify commands re-hash automatically.
- Independent `--kem` / `--sig` overrides so a strong KEM can pair with a
  lighter signature (the custom profile round-trips through both formats).

### Keys & CLI

- `keygen` generates the full hybrid keyset by default — ML-KEM + ML-DSA plus
  X25519, Ed25519, and ECDSA-P256 — so hybrid workflows work out of the box.
  `--classical` narrows the set; `--no-classical` keeps PQC-only.
- Every encrypt/decrypt prints the combination in effect (e.g.
  `suite ML-KEM-1024 + X25519 → HKDF-SHA-512 → ChaCha20-Poly1305`, plus
  `engine`/`signature`/`recipients` lines). New `pqforge inspect` describes any
  `.pqf`/`.pqfs`/key/signature file without decrypting it.

### Hardening & FIPS

- Caller metadata can no longer spoof any reserved container marker
  (`hybridKex`, `aeadSuite`, `recipients`, `recipientKeyId`) on any encrypt
  path.
- Streaming reader hardened against hostile containers (header/signature length
  caps enforced before allocation); NIST SP 800-38D 2³² frames-per-key bound
  enforced in nonce derivation.
- FIPS deployment layer: `PqFipsMode` (AES-256-GCM-only suites, PBKDF2-only
  wrapping when enabled), PBKDF2-HMAC-SHA256 key wrapping (SP 800-132), and a
  swappable `PqRandom.generator` for validated-module DRBGs.

### Web & portability

- The `.pqfs` codec is dart2js-safe: frame counters encode as two uint32 halves
  (`PqBytes.uint64`/`readUint64`, byte-identical wire format), and
  `PqStreamingEnvelope` ships in the core web-safe umbrella. Only the `dart:io`
  file plumbing (`PqForgeStreamCipher`) remains VM/native-only.
- Swappable lattice backend (`PqLatticeProvider`, `PqLattice.provider`) with the
  pure-Dart implementation as default and a reusable conformance / KAT harness.

### Tooling & CI

- `.github/workflows/release.yml`: `dart compile exe` binaries for
  linux-x64/macos-arm64/windows-x64 with SHA-256 checksums on `v*` tags.
- `tool/openssl_interop` (its own `publish_to: none` package, excluded from the
  published archive): proves both AEAD suites on both engines byte-identical
  with the system OpenSSL (cross-seal/open + tamper, enforced in CI) and
  measures the hardware ceiling. The published package contains no `dart:ffi`.
- CI enforces a streaming peak-RSS regression gate (1.5× amplification at
  64 MiB), repo-wide `dart format`/`analyze`, and a full CLI smoke.

### Documentation

- As-built performance/hybrid record and recommendation tracker:
  `doc/technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md`.

## 0.1.0

- Added algorithms, primitives, codecs,keys, recipes and service layers.
- Added binary and JSON envelope v1 formats.
- Added combined key bundles, portable key-store interfaces passphrase key wrapping, document signing, encrypted records/files, signed logs, identity bindings, artifact signing, dual-signature combiners, and isolate DTOs.
- Added the `/doc` documentation system, CI workflow, and expanded tests.
- Added typed ML-KEM, ML-DSA and SLH-DSA profiles for compact, balanced, and maximum parameter choices.
- Added ML-DSA detached signatures, ML-KEM KEM-DEM sealing/opening, signed encrypted envelopes, HKDF-SHA256 hybrid session derivation, AES-GCM helpers,transcript framing utilities, and strict byte-length checks.
- Added segmented examples and focused composition tests.
