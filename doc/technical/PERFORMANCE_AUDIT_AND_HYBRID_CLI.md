# PERFORMANCE AUDIT & HYBRID-ENCRYPTION CLI — RECOMMENDATIONS + PROGRESS TRACKER

**Audit date:** 2026-06-10 · **Audited tree:** `feature/performance-optimizations`
@ `64700c8` ("Speed optimization and parallization") · **Host:** i5-1135G7
(4 physical cores / 8 threads), Dart 3.12.0, linux_x64.
**Companions:** [SCOPE_AUDIT_AND_LIMITS.md](./SCOPE_AUDIT_AND_LIMITS.md) (capacity
limits) · [PERFORMANCE_OPTIMIZATIONS.md](./PERFORMANCE_OPTIMIZATIONS.md) (Phases 0–8
as built) · [PQFORGE_OPTIMIZATION_BLUEPRINT.md](./PQFORGE_OPTIMIZATION_BLUEPRINT.md).

This document is the follow-up audit the previous round called for: it hunts the
*remaining* performance gaps across every consumption profile (Flutter app, Dart
server, CLI, web), specifies the hybrid (ML-KEM + X25519) encryption feature the
CLI now ships, and tracks every recommendation to closure.

All numbers are **measured on this host** unless marked *projection*.

---

## 1. Progress tracker

Status legend: ✅ **shipped** (this change) · 📋 **recommended** (open) ·
🚫 **blocked** (external dependency) · ⏳ **partial**.

| ID | Finding / recommendation | Severity | Status |
| --- | --- | --- | --- |
| A1 | One-shot (<8 MiB) path hardwired to PointyCastle (~0.9 MiB/s) — `--engine` was ignored for small files | High | ✅ `encryptAsync`/`decryptAsync` run the DEM stage on any engine; all CLI one-shot paths use them (≈10× on sub-8 MiB files) |
| A2 | CLI could not produce hybrid (PQC + classical) ciphertext at all | High | ✅ Hybrid ML-KEM + X25519 KEM-DEM across `encrypt`, `decrypt`, `encrypt-folder`, `decrypt-folder`, `encrypt-media`, `decrypt-media`, `encrypt-text`, `decrypt-text`, `pack`, `unpack` |
| A3 | `keygen` required `--classical=<algo>` per algorithm; hybrid workflows broken out of the box | High | ✅ keygen emits ML-KEM + ML-DSA + X25519 + Ed25519 + ECDSA-P256 by default (`--no-classical` opts out, `--classical` narrows); classical keypairs generate concurrently |
| A4 | Algorithm combination in effect was invisible to operators | Medium | ✅ Every encrypt/decrypt prints `suite` / `engine` / `signature` detail lines; new `inspect` command describes any artifact without decrypting |
| A5 | Four M2-pattern redundant full-file copies in `bin/src/hybrid_commands.dart` | Low | ✅ `Uint8List.fromList(await readAsBytes())` → `await readAsBytes()` |
| A6 | Sync `decrypt` of a hybrid envelope would die deep in the AEAD with an opaque tag error | Medium | ✅ Clear `PqForgeException` guards on the sync paths; `hybridKex` metadata key reserved on every encrypt path |
| A7 | Engine provider→instance mapping duplicated (stream cipher, CLI) | Low | ✅ Single `aeadEngineForProvider` shared by stream cipher, async one-shot, CLI |
| R1 | `hybrid-sign`/`ecdsa-sign`/`hybrid-verify` hold the whole input in RAM (no pre-hash mode for GB-scale artifacts) | Medium | ✅ `--digest` on hybrid-sign/ecdsa-sign streams SHA-256 (O(1) memory, `PqBytes.sha256OfStream`), self-described in the signature JSON; verify re-hashes automatically — §8.1 |
| R2 | `keygen` Argon2id wraps run sequentially (~0.5 s × 5 with a passphrase) | Low | ✅ Wraps run on a bounded isolate pool (`--wrap-concurrency`, default 2, clamp 1–4); full default keygen-with-passphrase ≈ 2.9 s wall — §8.2 |
| R3 | CLI pins AES-256-GCM; ChaCha20-Poly1305 engines exist but are unreachable from the CLI | Medium | ✅ `--cipher chacha20-poly1305` on the 5 encrypt commands; recorded as an `aeadSuite` marker, decrypt auto-rebuilds its engine. **Pure-Dart ChaCha measures 30.4 MiB/s vs 11.5 AES — 2.6× bulk wherever hardware AES isn't dispatched** — §8.3 |
| R4 | `dart run` JIT startup adds ~2–3 s to every CLI invocation | Medium | ✅ `.github/workflows/release.yml` builds `dart compile exe` binaries (linux-x64 / macos-arm64 / windows-x64 + SHA-256) on `v*` tags |
| R5 | Multi-recipient envelopes (N keys, one payload) require N full encrypts today | Medium | ✅ Seal once, wrap the DEM key per extra recipient in `recipients[]` metadata — **no wire-format change**, both container formats, per-entry hybrid, keyId routing; CLI `--recipient-public` is repeatable — §8.4 |
| R6 | Hardware-AEAD FFI engine (OpenSSL EVP) — the GB/s ceiling vs 11 MiB/s today | High (servers with >10 GB workloads) | ✅ *as a dev tool, never a package feature*: `tool/openssl_interop` (own `publish_to: none` package, the same structure as pqcrypto's OpenSSL ML-KEM interop) proves byte-compatibility and measures the ceiling. The published package contains no `dart:ffi` by design — it is pure Dart and web-first, and FFI does not exist on the web — §8.5 |
| R7 | Native lattice (ML-KEM/ML-DSA) via FFI | Low (lattice ops are not the bottleneck) | 🚫 Deliberately not shipped (supply chain + the same pure-Dart policy as R6); host-build guide exists: [PHASE7_NATIVE_LATTICE_FFI.md](./PHASE7_NATIVE_LATTICE_FFI.md) |
| R8 | Parsed/preprocessed public-key reuse in `pqcrypto` (folder workloads redo PK parsing per file) | Medium | 🚫 Blocked on an upstream `pqcrypto` API change; a parsed/preprocessed public-key reuse proposal is tracked against `pqcrypto` |
| R9 | Streaming frame pipelining (overlap read → seal → write) | Low | ✅ `encryptFile` double-buffers (the next frame reads from disk while the current one seals/writes); `decryptStream` prefetches one frame; in-flight reads are drained on failure so cleanup semantics are unchanged — §8.6 |
| R10 | Web profile cannot stream (`.pqfs` uses `setUint64`, dart2js-unsafe) | Info | ✅ Frame counters now encode as two uint32 halves (`PqBytes.uint64`/`readUint64` — byte-identical wire format, VM-oracle-tested); the codec is dart2js-safe and exported from the core umbrella — §8.7 |

---

## 2. What shipped in this change

### 2.1 Hybrid (ML-KEM + X25519) encryption, end to end

Confidentiality now holds **as long as either assumption stands** — Module-LWE
*or* Curve25519 DLP — matching the defence-in-depth posture of
`draft-ietf-tls-hybrid-design` (concatenate-then-KDF, classical share first).

**Key schedule** (shared verbatim by the one-shot and streaming paths via
`PqHybridKemDem`):

```text
(ek, ct, ssPQ)  = ML-KEM.Encaps(recipientKemPk)
(ephSk, ephPk)  = X25519.KeyGen()                  # fresh per file
ssC             = X25519(ephSk, recipientX25519Pk)
demKey = HKDF-SHA-256|SHA-512(                     # SHA-512 iff ML-KEM-1024
           ikm  = ssC ‖ ssPQ,                      # classical first, no framing
           salt = ct ‖ ephPk,
           info = "pqforge/hybrid-kem-dem/<profile>/<kem-id>/x25519/v1")
```

**Container encoding:** zero format change. The marker rides in envelope/header
metadata:

```json
"hybridKex": {"algorithm": "x25519", "ephemeralPublicKey": "<base64 32B>"}
```

Security properties:

* **Self-authenticating marker.** `ephPk` is the KDF salt and the algorithm id
  is in the KDF info, so tampering either yields a different DEM key and the
  very first AEAD tag check fails — even on *unsigned* envelopes. Signed
  envelopes additionally bind the metadata under ML-DSA; `.pqfs` binds it into
  every frame's AAD via `SHA-256(headerCore)`.
* **Shared-secret hygiene.** `ssC`, the ephemeral secret, and the concatenated
  IKM are wiped (`PqForgeCombiner.wipe`) in `finally` blocks.
* **FIPS posture.** The construction is the SP 800-56C Rev 2 §2 "hybrid"
  shared secret (`Z' = Z ‖ T` through an approved KDF), so an approved
  algorithm (ML-KEM) always contributes; X25519 acts as the auxiliary input.
  `PqFipsMode` continues to gate suite/KDF as before.

**Library surface** (exported from `package:pqforge/pqforge.dart`):

* `PqForge.encryptAsync(...{recipientKexPublicKey, engine})` /
  `PqForge.decryptAsync(...{recipientKexSecretKey, engine})` — extension
  `PqForgeAsync`; hybrid auto-detected on decrypt from the marker.
* `PqForgeStreamCipher.encryptFile/encryptStream({recipientKexPublicKey})`,
  `decryptFile/decryptStream({recipientKexSecretKey})` + the
  `*InBackground` isolate variants.
* `PqHybridKemDem` — `deriveDemKey`, `encapsulate`, `demKeyForOpen`,
  `isHybrid`, `parseMetadata`, `combinerProfileFor`.
* `PqForgeHybridKeyAgreement.x25519SharedSecret` — raw-bytes ECDH.

**CLI surface:**

```bash
# all keys (PQC + classical) are now the default
pqforge keygen --key-id vault --out-dir keys --passphrase-env PQFORGE_PASSPHRASE

# hybrid: --hybrid finds keys/vault.x25519.public.json by convention,
# or pass --recipient-x25519-public explicitly
pqforge encrypt --hybrid --recipient-public keys/vault.kem.public.json \
  --in report.pdf --out report.pdf.pqf

# decrypt auto-detects hybrid and auto-finds vault.x25519.secret[.wrapped].json
pqforge decrypt --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE --in report.pdf.pqf --out report.pdf
```

Every bulk command accepts the same pair of options; folder commands resolve
the X25519 key opportunistically because a tree may mix hybrid and pure-PQC
entries.

### 2.2 The combination is always visible (A4)

```text
✓ Encrypted to streaming maximum envelope (signed) — 9 frames
  suite      ML-KEM-1024 + X25519 → HKDF-SHA-512 → AES-256-GCM
  engine     cryptography (hardware-capable)
  signature  ML-DSA-87
```

`pqforge inspect --in <file>` prints the same suite line (plus profile, frame
size, AAD binding, metadata) for any `.pqf`/`.pqfs`/key/signature file without
decrypting anything.

### 2.3 Engine-aware one-shot path (A1) — the headline win

`PqForge.encrypt` (sync) is pinned to PointyCastle by its signature. The new
async pair runs the DEM stage on any `PqForgeAeadEngine` and produces
**byte-compatible envelopes** (the envelope never records the engine; AES-GCM
is AES-GCM). All ten CLI bulk paths now use it.

| One-shot 7 MiB encrypt (below streaming threshold) | before | after |
| --- | --- | --- |
| `--engine cryptography` (default) | ~18.5 s (flag silently ignored) | **~4.5 s** wall, of which ~2.5 s is `dart run` JIT (R4) — AEAD ≈ 2 s |
| `--engine pure-dart` | ~18.5 s | ~18.5 s (reference path, unchanged) |

### 2.4 Keygen defaults (A3) + measured costs

`pqforge keygen` now emits 10 files by default (5 keypairs). Classical
generation is concurrent (`Future.wait`); the added cost over the old
PQC-only default is ~20 ms — noise next to Argon2id wrapping:

| op (pure Dart, this host) | cost |
| --- | --- |
| X25519 keygen / ECDH | 2.8 ms / 3.3 ms |
| Ed25519 keygen | 4.0 ms |
| ECDSA-P256 keygen (PointyCastle) | **17.3 ms** (the slowest of the five) |
| ML-KEM-1024 + ML-DSA-87 keygen | ~8 ms combined |
| Argon2id wrap, per secret (2 it, 64 MiB, 4 lanes) | ~0.4–0.6 s — dominates with a passphrase (see R2) |

**Hybrid runtime overhead per file:** one X25519 keygen + one ECDH at encrypt
(~3–6 ms), one ECDH at decrypt (~3 ms) — constant, independent of file size.
At 100 MiB it is noise; only sub-4 KiB bulk workloads will notice (use `pack`
for those anyway).

---

## 3. Recipe → fastest-path matrix (all profiles)

| Workload | Use | Why it is the fast path |
| --- | --- | --- |
| File < 8 MiB | `encrypt` (one-shot, auto) | `encryptAsync` + cryptography engine (A1); ~3× payload RAM |
| File ≥ 8 MiB | `encrypt` (auto-streams `.pqfs`) | bounded ~2-frame memory, O(1) signing |
| Few large files | `encrypt-folder --concurrency <physical cores>` | per-file isolates; scaling follows physical cores (~3.3× on 4C) |
| Many tiny files | `pack` | one KEM + one signature for the whole tree; ~100× less ciphertext than per-file envelopes for 1000 small files |
| Text/tokens/records | `encrypt-text` / library recipes | one-shot; payload too small for streaming to matter |
| Mixed/unknown | `encrypt` per file | the 8 MiB threshold auto-routes |
| Defence-in-depth mandate | add `--hybrid` to any of the above | +3–6 ms/file fixed cost (§2.4) |

---

## 4. Per-profile algorithm guidance

| Profile | Suite | Per-file fixed cost (encaps+decaps / sign+verify) | Choose when |
| --- | --- | --- | --- |
| `compact` | ML-KEM-512 + ML-DSA-44 | ~1.8 ms / ~11 ms | IoT/embedded, high-volume small records, NIST level 1/2 acceptable |
| `balanced` | ML-KEM-768 + ML-DSA-65 | ~3 ms / ~12 ms | the TLS-ecosystem default posture (level 3) |
| `maximum` (CLI default) | ML-KEM-1024 + ML-DSA-87 | ~4.3 ms / ~12 ms | archives, long-lived secrets (level 5) |
| decoupled | `--kem maximum --sig compact` | strong KEM, 2420-B instead of 4627-B signatures | bulk payloads where header size matters but confidentiality must be maximal |

Notes:

* ML-DSA sign cost is rejection-sampled — treat any parameter set as ≈5–10 ms.
* The AEAD engine, not the lattice, is the bulk-throughput lever; profile
  choice changes per-file constants and sizes, not MiB/s.
* Hybrid pairs every profile with X25519; ML-KEM-1024 upgrades the combiner
  KDF to HKDF-SHA-512 automatically.

---

## 5. Platform playbooks

### 5.1 Flutter apps (Android / iOS / desktop)

1. **Register hardware crypto once, at startup, on the root isolate:**

   ```dart
   import 'package:cryptography_flutter/cryptography_flutter.dart';
   void main() { FlutterCryptography.enable(); runApp(...); }
   ```

   The default engine then dispatches AES-GCM to AES-NI/ARMv8 Crypto via OS
   bindings — GB/s-class instead of ~11 MiB/s pure Dart.
2. **Never run bulk crypto on the UI isolate.** Use
   `PqForgeStreamCipher.encryptFileInBackground(...)` /
   `decryptFileInBackground(...)` (Axis A). Fresh isolates do not see the
   root-isolate Flutter registration and fall back to fast pure Dart — that is
   the correct trade: a non-blocked UI beats raw throughput. For
   hardware-speed *and* off-UI, run the call on the root isolate behind a
   `compute`-style progress UI only for short jobs.
3. Mobile CPUs without AES instructions (and any path that falls back to pure
   Dart, e.g. background isolates) favour ChaCha20-Poly1305: **30.4 MiB/s vs
   11.5 MiB/s AES in pure Dart (2.6×)**. CLI: `--cipher chacha20-poly1305`;
   library: pass the suite to `aeadEngineForProvider`/`forProvider`. Decrypt
   auto-detects from the `aeadSuite` marker (R3, §8.3).
4. Wrap/unwrap (Argon2id, 64 MiB) must also go through `Isolate.run` — it is a
   deliberate ~0.5 s CPU burn.
5. Key custody: generate on-device (`keygen` parity via library), wrap with a
   passphrase from `flutter_secure_storage`-held entropy, and prefer hybrid
   (`recipientKexPublicKey`) for anything synced to servers you do not control.

### 5.2 Dart servers (incl. Serverpod)

1. Default engine is already the fast one; prefer `--cipher
   chacha20-poly1305` for bulk on hosts whose AES stays in pure Dart (2.6×,
   §8.3). The ~100× hardware ceiling (OpenSSL ≈ 1.1 GB/s, §8.5) is
   deliberately out of scope for the package itself — pqforge stays pure
   Dart; shell out to `openssl` or front the storage layer with it when a
   workload truly needs GB/s.
2. Size worker pools by **physical cores** (`--concurrency`, default
   `min(CPU, 8)`); SMT threads add nothing to AES in pure Dart.
3. AOT-compile entrypoints (`dart compile exe`) — JIT warmup on short-lived
   container processes is pure waste (R4).
4. Use `pack` for cold archival of many small rows/files; `encrypt-folder`
   when per-file random access matters.
5. Long-lived processes: construct one `PqForgeStreamCipher` and reuse it; the
   engine is stateless and safe to share per isolate.
6. Serverpod: do the KEM/DEM in endpoint isolates freely (ops are ms-scale);
   push anything ≥ 8 MiB through the streaming API on `Isolate.run`.

### 5.3 CLI

1. Defaults are now optimal (fast engine on every path, streaming auto-route,
   hybrid one flag away). The remaining tax is `dart run` JIT (~2–3 s): ship
   AOT binaries (R4) — `dart compile exe bin/pqforge.dart -o pqforge`.
2. `--engine pure-dart` exists for auditability/reference runs, not speed.
3. Folder jobs: let the default concurrency stand unless the disk is the
   bottleneck (spinning rust → `--concurrency 2`).

### 5.4 Web

* Import `package:pqforge/pqforge.dart` only (core is dart2js-safe). One-shot
  envelopes, signing, hybrid one-shot (`encryptAsync`) all work; `package:cryptography`
  uses WebCrypto where available.
* The `.pqfs` **codec** (`PqStreamingEnvelope`) is now dart2js-safe too (R10,
  §8.7) and ships in the core umbrella: frame counters encode as two uint32
  halves, so a browser app can frame/seal/open `.pqfs` content over its own
  transport. Only the `dart:io` file plumbing (`PqForgeStreamCipher`) remains
  VM-only; `dart compile wasm` also works.
* This web-first identity is why the package contains no `dart:ffi` by
  design (see R6/R7): FFI does not exist on the web.

---

## 6. Design notes (as built in §8)

### 6.1 R1 — large-artifact hybrid signing

`hybrid-sign` buffers the whole input. ML-DSA already supports `preHash`; the
classical side needs Ed25519ph (not exposed by `package:cryptography`) or an
explicit hash-then-sign convention (`sign SHA-256(file)` with the hash recorded
in the signature JSON, as `sign --kind artifact` already does). Recommended
shape: `hybrid-sign --digest` flag implementing artifact-style pre-hashing for
both legs; streaming SHA-256 keeps memory O(1).

### 6.2 R2 — parallel key wrapping

`Future.wait` over `Isolate.run(wrapKeyWithPassphrase...)` with concurrency 2–3
takes keygen-with-passphrase from ~2.5 s to ~1 s. Each Argon2id instance holds
64 MiB (`memoryPowerOf2: 16`), so cap wrap concurrency at 2 on small devices or
expose `--wrap-concurrency`.

### 6.3 R3 — `--cipher chacha20-poly1305`

Both engines already implement the suite and the wire format carries the same
12-byte nonce/16-byte tag geometry. Needs: a `--cipher` flag on the 10 bulk
commands, suite id surfaced in `inspect`/suite lines (read it from the engine,
not a constant), and a FIPS-mode rejection (`PqFipsMode.requireApprovedSuite`
already throws for ChaCha20).

### 6.4 R4 — AOT release binaries

CI job: `dart compile exe bin/pqforge.dart` per OS/arch, attach to releases.
Removes the ~2–3 s JIT tax measured in §2.3 and makes CLI timings match
library benchmarks.

### 6.5 R5 — multi-recipient envelopes

Today N recipients ⇒ N× the whole pipeline. Sketch: keep one random DEM key,
AEAD-seal the payload once, then per recipient store
`KEM-encapsulate → HKDF → AES-key-wrap(demKey)` (~1.6 KB each for ML-KEM-1024).
Requires a v2 envelope field (`recipients[]`) — the only open item in this
audit that touches the wire format.

### 6.6 R6 — FFI AEAD engine

The package contains no `dart:ffi` and acquires none through this item: the
library is pure Dart and web-first, and FFI does not exist on the web. R6's
substance — OpenSSL correctness verification and ceiling measurement — is
implemented as the `tool/openssl_interop` dev-tool package (its own
`publish_to: none` pubspec, the same structure pqcrypto uses for its OpenSSL
EVP ML-KEM interop). As-built record in §8.5. The original sketch of an
in-package opt-in EVP engine over the `PqForgeAeadEngine` seam is retained
here only for context and is not a direction the library takes.

### 6.7 R9 — frame pipelining

`encryptFile` is strictly read→seal→write sequential. Overlapping with a
2-frame ring buffer is a ~1.2–1.5× *projection* (I/O-bound disks benefit most),
at the cost of harder failure-cleanup semantics. Revisit only after R6 makes
the AEAD no longer the bottleneck.

---

## 7. Verification & reproduction

```bash
dart analyze                                   # 0 issues
dart format --set-exit-if-changed lib bin test # CI-enforced
dart test                                      # 198 passed, 4 benchmark-tagged skipped
dart test test/pq_hybrid_encryption_test.dart  # hybrid/engine tests
dart test test/pq_multi_recipient_test.dart    # R5 (one-shot + streaming)
dart test test/pq_cipher_suite_selection_test.dart  # R3 (marker, rebuild, FIPS)
dart test test/pq_bytes_uint64_test.dart       # R10 portability + R1 stream hash

# per-op probes (benchmark-tagged, opt-in)
PQFORGE_PROBE=1 dart test -t benchmark test/performance_probe_test.dart
PQFORGE_BENCH_MODE=streaming dart test -t benchmark test/benchmark_io_test.dart

# OpenSSL byte-compatibility + ceiling measurement (dev tool, R6/§8.5)
dart pub get --directory tool/openssl_interop
(cd tool/openssl_interop && REQUIRE_OPENSSL=1 dart run bin/verify_interop.dart --bench)
```

Manual hybrid smoke (mirrors what was run for this audit):

```bash
pqforge keygen --key-id vault --out-dir keys            # 10 files, suite shown
pqforge encrypt --hybrid --recipient-public keys/vault.kem.public.json \
  --in big.bin --out big.bin.pqf                        # suite: ML-KEM-1024 + X25519
pqforge inspect --in big.bin.pqf                        # shows the hybrid suite
pqforge decrypt --recipient-secret keys/vault.kem.secret.json \
  --in big.bin.pqf --out big.out.bin                    # auto-detects + auto-finds key
```

---

## 8. As-built record (audited 2026-06-12)

Implements every 📋 item from §1: R1–R5 and R9–R10 in the package and CLI,
R6 as the `tool/openssl_interop` dev-tool harness. Verification: 198 tests,
repo-wide analyze/format clean, the full CLI smoke in CI, and OpenSSL 3.0.13
byte-compatibility on all four suite × engine combinations. Implementation
constraints worth knowing when extending these paths are collected in §8.8.

### 8.1 R1 — digest-mode signing

`hybrid-sign --digest` / `ecdsa-sign --digest` sign
`lengthPrefixed("pqforge/digest-input/sha-256/v1", SHA-256(file))` where the
hash is computed by the new `PqBytes.sha256OfStream` — one digest update per
chunk, O(1) memory for any artifact size. The mode is recorded as
`"digest": "sha-256"` in the signature JSON, so the verify commands re-hash
automatically; the domain label makes raw and digest modes uncollidable.

### 8.2 R2 — parallel key wrapping

`keygen` wraps secrets on a bounded `Isolate.run` pool (`--wrap-concurrency`,
default 2, clamped 1–4 because each Argon2id instance pins its own 64 MiB
arena). Full default keygen (5 keypairs, wrapped): **≈ 2.9 s wall** on this
host. The wrap closure lives in a top-level function so its context chain
holds only sendable parameters (§8.8).

### 8.3 R3 — `--cipher chacha20-poly1305`

Available on `encrypt`, `encrypt-folder`, `encrypt-media`, `pack` (and the
text path via the library); decrypt needs no flag — a non-default suite is
recorded as an `aeadSuite` metadata marker and every open path rebuilds its
engine (same provider) to match. AES output stays marker-free and
byte-compatible with all prior releases. The marker is tamper-evident even
unsigned: stripping it makes the opener run the wrong cipher and fail the
tag (test-covered). FIPS mode rejects the suite at every entry point.

Measured (interop tool, this host): pure-Dart `cryptography` engine —
**ChaCha20-Poly1305 30.4 MiB/s vs AES-256-GCM 11.5 MiB/s (2.6×)**. Where
Flutter's root-isolate hardware AES is not in play (servers, CLI, background
isolates), ChaCha is now the bulk-throughput recommendation.

### 8.4 R5 — multi-recipient encryption

Implemented with **no wire-format change** (the §6.5 sketch anticipated a v2
envelope field; none is needed). The payload is sealed once under the
primary's DEM key (KEM-DEM or hybrid, unchanged — single-recipient output is
byte-identical); each additional recipient gets a `recipients[]` metadata
entry wrapping that DEM key:

```text
(ct_i, ss_i) = ML-KEM.Encaps(recipient_i.kemPk)
kek_i        = HKDF(ss_i)   # salt = ct_i [‖ ephPk_i for hybrid entries]
entry_i      = AES-256-GCM(kek_i, nonce_i, demKey)   # 48-byte wrap
```

Properties: ~1.6 KB + ~2 ms per extra recipient (ML-KEM-1024) instead of a
full re-encryption; entries may individually be hybrid (own ephemeral X25519);
`recipientKeyId` routes the opener straight to its entry; a corrupted entry
can only deny service (each wrap is AEAD-authenticated under a KEK only that
recipient derives); signed envelopes/headers bind the whole map. Works
identically for one-shot envelopes and `.pqfs` streams (the stream resolves
the winning key on the first frame). A hybrid primary never blocks a
plain additional recipient — the hybrid-key requirement is deferred when
entries exist. Sync `decrypt` still serves the primary and points additional
recipients at `decryptAsync`.

CLI: `--recipient-public` is repeatable on `encrypt`, `encrypt-folder`,
`encrypt-text`, `encrypt-media`, `pack` (first = primary); decrypt side needs
nothing new. With `--hybrid`, the X25519 key is required for the primary and
resolved opportunistically for additional recipients (missing → that entry is
post-quantum-only).

### 8.5 R6 — OpenSSL as a dev tool, pure Dart as architecture

pqforge is pure Dart and web-first; `dart:ffi` does not exist on the web, so
no FFI engine belongs in the package. R6's substance — proving correctness
against OpenSSL and quantifying the ceiling — is implemented as
`tool/openssl_interop` (`openssl_pqforge_interop`, `publish_to: none`,
`.pubignore`d out of the published archive), the same shape as pqcrypto's
`tool/openssl_interop` ML-KEM harness:

* `lib/openssl_aead.dart` — EVP AES-256-GCM/ChaCha20-Poly1305 via the
  *system* libcrypto (`LIBCRYPTO_PATH` override, platform candidates, null on
  absence; nothing bundled).
* `bin/verify_interop.dart` — for every suite × engine: **byte-identical
  seals**, cross-opens, tamper detection both ways; `--bench` for throughput.
  CI job `openssl-interop` enforces it on every push (`REQUIRE_OPENSSL=1`).

Measured (this host, OpenSSL 3.0.13, 1 MiB frames incl. FFI copies):
AES-256-GCM **1122.8 MiB/s**, ChaCha20-Poly1305 **1049.2 MiB/s** — vs 11.5 /
30.4 MiB/s pure Dart. That ~37–98× gap is the documented cost of the pure-Dart
guarantee; workloads that truly need it should shell out to `openssl` or
encrypt at the storage layer, not extend pqforge.

### 8.6 R9 — frame pipelining

`encryptFile` now double-buffers: the next frame's disk read overlaps the
current frame's seal+write (separate file handles; +1 frame of memory, still
within the 1.5× CI gate). `decryptStream` prefetches one frame while the
current one is opened; validation order is observably unchanged and a failing
open always drains the in-flight read before rethrowing, so the
delete-partial-output cleanup semantics survive. Gains scale with how close
the AEAD is to disk speed — modest today, free thereafter.

### 8.7 R10 — dart2js-safe `.pqfs` codec

`PqBytes.uint64`/`readUint64` encode/decode big-endian uint64 as two uint32
halves (values ≥ 2^53 rejected — nothing legitimate produces them and they
are not web-exact). The codec's nonce/AAD/frame-header arithmetic uses them,
is proven byte-identical against a `ByteData.setUint64` VM oracle, and
`pq_streaming_envelope.dart` moved into the core web-safe umbrella export.
The wire format is unchanged.

### 8.8 Implementation constraints

* **Isolate closures must be hoisted.** A closure passed to `Isolate.run`
  carries its full lexical context chain; written inline in a pooled task it
  would capture the `Semaphore` (whose `Completer`s are unsendable) and fail
  at send time. Every isolate entry point in the CLI is therefore a top-level
  function whose context holds only sendable parameters
  (`_wrapKeyInIsolate`, `_encryptFolderEntryInIsolate`,
  `_decryptFolderEntryInIsolate`).
* **Hybrid key resolution is strict for the primary, opportunistic
  otherwise.** On the encrypt side, `--hybrid` requires the primary
  recipient's X25519 key (it defines the envelope's key schedule) and
  resolves additional recipients' keys when present, falling back to
  post-quantum-only wrap entries. On the decrypt side, a hybrid input with
  `recipients[]` entries resolves a missing X25519 key to null and defers to
  the library, which either opens a wrap entry or raises its own descriptive
  error — the CLI never pre-empts a path the library can still satisfy.

The CI smoke exercises: default keygen (10 files, pooled wrapping), hybrid +
ChaCha20-Poly1305 + two-recipient encryption in one envelope, decryption by
both the hybrid primary and the X25519-less additional recipient, `inspect`,
and both digest-mode signature flows with a tamper-rejection check.
