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
| R1 | `hybrid-sign`/`ecdsa-sign`/`hybrid-verify` hold the whole input in RAM (no pre-hash mode for GB-scale artifacts) | Medium | 📋 ML-DSA side supports `preHash`; Ed25519ph/streaming-SHA-256 design needed for the classical side — see §6.1 |
| R2 | `keygen` Argon2id wraps run sequentially (~0.5 s × 5 with a passphrase) | Low | 📋 Parallel wrapping via `Isolate.run` is a ~2.5 s → ~1 s win but multiplies peak RAM by the wrap concurrency (64 MiB each) — see §6.2 |
| R3 | CLI pins AES-256-GCM; ChaCha20-Poly1305 engines exist but are unreachable from the CLI | Medium | 📋 `--cipher chacha20-poly1305` flag; wins on no-AES-NI mobile/ARM — see §6.3 |
| R4 | `dart run` JIT startup adds ~2–3 s to every CLI invocation | Medium | 📋 Ship `dart compile exe` release binaries (CI artifact) — see §6.4 |
| R5 | Multi-recipient envelopes (N keys, one payload) require N full encrypts today | Medium | 📋 Wrap one DEM key to N recipients — format addition, design sketch in §6.5 |
| R6 | Hardware-AEAD FFI engine (OpenSSL EVP / CryptoKit / Conscrypt) — the 9.5 GB/s ceiling vs 11 MiB/s today | High (servers with >10 GB workloads) | 📋 `PqForgeAeadEngine` is the seam; same supply-chain caveats as R7 — see §6.6 |
| R7 | Native lattice (ML-KEM/ML-DSA) via FFI | Low (lattice ops are not the bottleneck) | 🚫 Deliberately not shipped (supply chain); host-build guide exists: [PHASE7_NATIVE_LATTICE_FFI.md](./PHASE7_NATIVE_LATTICE_FFI.md) |
| R8 | Parsed/preprocessed public-key reuse in `pqcrypto` (folder workloads redo PK parsing per file) | Medium | 🚫 Blocked on upstream API; spec already written: [PQCRYPTO_PARSED_PK_PROPOSAL.md](./PQCRYPTO_PARSED_PK_PROPOSAL.md) (user owns `pqcrypto`) |
| R9 | Streaming frame pipelining (overlap read → seal → write) | Low | 📋 ~1.2–1.5× *projection* on fast disks; complexity vs gain currently unfavourable — see §6.7 |
| R10 | Web profile cannot stream (`.pqfs` uses `setUint64`, dart2js-unsafe) | Info | 📋 WASM compilation works today; a `BigInt`-based frame counter fallback would unlock dart2js streaming if ever needed — see §5.4 |

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
3. Mobile CPUs without AES instructions favour ChaCha20-Poly1305 — blocked on
   R3 for the CLI but available today in-library via
   `PqForgeStreamCipher(engine: PqForgeCryptographyAeadEngine(PqForgeCipherSuite.chaCha20Poly1305))`.
4. Wrap/unwrap (Argon2id, 64 MiB) must also go through `Isolate.run` — it is a
   deliberate ~0.5 s CPU burn.
5. Key custody: generate on-device (`keygen` parity via library), wrap with a
   passphrase from `flutter_secure_storage`-held entropy, and prefer hybrid
   (`recipientKexPublicKey`) for anything synced to servers you do not control.

### 5.2 Dart servers (incl. Serverpod)

1. Default engine is already the fast one; for >10 GB/day workloads the FFI
   AEAD engine (R6) is the next 100×.
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
* `.pqfs` streaming is VM/WASM-only today (`setUint64`) — R10 tracks the
  dart2js fallback; compile with `dart compile wasm` to stream in the browser.

---

## 6. Open recommendations (design notes)

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

`PqForgeAeadEngine` was built as the seam. An OpenSSL EVP binding (Linux
servers) closes the 11 MiB/s → ~9.5 GB/s gap on exactly the workloads where
pure Dart cannot compete. Carries the same host-build/supply-chain policy as
the lattice FFI guide; keep it an opt-in provider, never the default.

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
dart test                                      # 171 passed, 4 benchmark-tagged skipped
dart test test/pq_hybrid_encryption_test.dart  # the 14 hybrid/engine tests added here

# per-op probes (benchmark-tagged, opt-in)
PQFORGE_PROBE=1 dart test -t benchmark test/performance_probe_test.dart
PQFORGE_BENCH_MODE=streaming dart test -t benchmark test/benchmark_io_test.dart
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
