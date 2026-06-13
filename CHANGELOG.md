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
- Added typed ML-KEM and ML-DSA profiles for compact, balanced, and maximum parameter choices.
- Added ML-DSA detached signatures, ML-KEM KEM-DEM sealing/opening, signed encrypted envelopes, HKDF-SHA256 hybrid session derivation, AES-GCM helpers,transcript framing utilities, and strict byte-length checks.
- Added segmented examples and focused composition tests.
