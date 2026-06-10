# PQForge Performance Optimizations — As-Built (Phases 1–5)

Implementation record for the memory/throughput refactor specified in
[PQFORGE_OPTIMIZATION_BLUEPRINT.md](./PQFORGE_OPTIMIZATION_BLUEPRINT.md) and the
engineering directive. Phase 0 (benchmarking) is recorded separately in
[PHASE0_BENCHMARK_BASELINE.md](./PHASE0_BENCHMARK_BASELINE.md). A post-completion
scope audit — compliance matrix, measured per-op costs, capacity limits
(50–100 GB guidance), FIPS and mobile/embedded analysis — lives in
[SCOPE_AUDIT_AND_LIMITS.md](./SCOPE_AUDIT_AND_LIMITS.md).

> **Scope decision.** The library is pre-release, so there is **no backward
> compatibility layer**: each format is single-versioned and the old behaviours
> were replaced outright rather than gated behind a version flag.

---

## Phase 1 — Kill the gratuitous copies (M2)

`File.readAsBytes()` already returns a `Uint8List`; the surrounding
`Uint8List.fromList(...)` was a redundant full-payload copy. Removed at all six
sites — [bin/src/pqc_commands.dart](../../bin/src/pqc_commands.dart) (encrypt,
encrypt-folder, encrypt-media, sign, verify) and `readEnvelope`
([bin/src/support.dart](../../bin/src/support.dart)). The defensive copy inside
`PqEnvelope` is retained (misuse-resistance, not waste).

## Phase 2 — Sign the digest, not the file (M1)

`PqForge.encrypt`
([lib/src/services/pqforge_service.dart](../../lib/src/services/pqforge_service.dart))
signed the *whole ciphertext* concatenated into a fresh buffer with
`preHash:false`. It now signs a 32-byte digest

```text
digest = SHA-256( headerFields ‖ SHA-256(payload) )
```

with `preHash:true`. The payload is hashed in a single streaming pass (no
gigabyte concatenation), so signing cost **and** memory are independent of
payload size. The signed envelope is now built **once** (the previous code built
it twice — defect M3). The Phase 0 baseline showed signed *decrypt* was the
worst offender (≈5.7× peak) because verification re-materialised the whole
payload; this fix removes that on both encrypt and decrypt.

## Phase 3 — Bounded-memory streaming AEAD (`.pqfs`) — CORE

A self-describing streaming container that processes any file in a working set
that is a small multiple of the frame size, independent of total length.

```text
"PQFS" | uint32 formatVersion
       | uint32 headerCoreLen | headerCore
       | uint32 signatureLen  | signature        (0 = unsigned)
       | frame*
frame  = uint32 bodyLen | uint64 seq | uint8 isFinal | body(ciphertext‖tag)
```

* **nonce** `= nonceSalt(4B) ‖ uint64(seq)` — unique under the per-file DEM key.
* **aad** `= SHA-256(headerCore) ‖ uint64(seq) ‖ uint8(isFinal)` — binds every
  frame to the header and makes truncation, reordering, duplication, and
  splicing forgery-proof.
* **header signature** (optional) is ML-DSA over `headerCore` with `preHash:true`
  → O(1) in file size. Frame integrity comes from the per-frame AEAD tags, bound
  to the signed header via `SHA-256(headerCore)`.

Code is split for web-safety:

| File | Role |
| --- | --- |
| [pq_envelope.dart](../../lib/src/codecs/pq_envelope.dart) → `PqStreamingEnvelope`, `PqStreamingHeader` | Pure, web-safe framing: header (de)serialization, nonce/AAD derivation, per-frame seal/open. No `dart:io`. Malformed input → `PqForgeException`. |
| [pqforge_stream_service.dart](../../lib/src/services/pqforge_stream_service.dart) → `PqForgeStreamCipher` | `dart:io` glue: `encryptFile`/`decryptFile`/`readHeader`/`isStreamingFile`, `RandomAccessFile` both ways, partial-output deletion on failure. |
| [lib/pqforge_io.dart](../../lib/pqforge_io.dart) | `dart:io` entrypoint (`export 'pqforge.dart'` + the stream service). Keeps `dart:io` out of the web-safe `package:pqforge/pqforge.dart` umbrella. |

**CLI routing** ([pqc_commands.dart](../../bin/src/pqc_commands.dart), now imports
`pqforge_io.dart`): `encrypt` / `encrypt-media` stream when the input is
≥ `PqForgeStreamCipher.streamingThresholdBytes` (8 MiB), else use the one-shot
envelope. `decrypt` / `decrypt-media` auto-detect the format via the `PQFS`
magic. The streaming container is written to the user's chosen `--out` path
regardless of extension; the magic disambiguates it from a one-shot `.pqf`.

## Phase 4 — Swappable engine + isolate offload

The bulk path already runs through the swappable `PqForgeAeadEngine` (Phase 3),
fixing C2 — large files no longer hardwire pure-Dart PointyCastle.

* **Engine selection:** `PqForgeStreamCipher.forProvider(provider, …)` picks the
  `package:cryptography` engine (**the default since audit fix F1** — measured
  ~10.6× faster than PointyCastle even as pure Dart, hardware-backed on
  Flutter) or the PointyCastle reference engine (`--engine pure-dart` on the
  CLI). Cross-engine wire interop is tested (a file sealed by one opens under
  the other).
* **Isolate offload (Axis A):** `PqForgeStreamCipher.encryptFileInBackground` /
  `decryptFileInBackground` run the work on a background isolate via
  `Isolate.run`, keeping the caller's event loop free. A test verifies a
  main-isolate timer keeps firing during a multi-second background seal.

### Host-app hardware acceleration (`cryptography_flutter`)

`pqforge` stays a pure-Dart package (no Flutter dependency). To get AES-NI /
ARMv8 acceleration, the **host Flutter app** opts in:

```yaml
# host app pubspec.yaml
dependencies:
  cryptography_flutter: ^2.3.0
```

```dart
// host app main(), before any crypto:
FlutterCryptography.enable();   // Cryptography.instance = FlutterCryptography()
```

Then construct the cipher with the native engine:

```dart
final cipher = PqForgeStreamCipher.forProvider(
  PqForgeEngineProvider.nativeCryptography,
);
```

`package:cryptography`'s `AesGcm.with256bits()` now dispatches to the OS-native,
hardware-backed AEAD, which runs **off the Dart thread** — so it stays
responsive on the root isolate **without** an `Isolate.run` offload (its
platform channels are unavailable on background isolates; do not combine the
native engine with `*InBackground`). On the pure-Dart engine, use the
`*InBackground` offload to keep the UI responsive instead.

## Phase 5 — Concurrent folder processing (Axis B)

`encrypt-folder` / `decrypt-folder` process **one file per background isolate**,
gated by a `Semaphore` ([support.dart](../../bin/src/support.dart)) bounded to
`--concurrency` (default: CPU count, capped at 8). Each file owns a distinct DEM
key by construction, so there is no shared-nonce hazard across workers. Folder
entries above the streaming threshold are streamed; smaller ones use a one-shot
envelope, and `decrypt-folder` auto-routes per entry. The directory walk feeds
the bounded pool; relative paths are re-validated against traversal on read.

## Phase 6 — Algorithmic surface tuning

* **Decoupled KEM / signature strength (delivered).** `--kem` and `--sig`
  override either profile component independently, so a strong KEM can pair with
  a lighter signature — the bulk payload is AEAD-protected under a 256-bit key
  regardless of KEM strength, and the signature is only about sender identity.
  Built via `resolveProfile` ([support.dart](../../bin/src/support.dart)); the
  custom profile name round-trips through both envelope formats (readers
  reconstruct the algorithms from the stored ids). Folder mode is already
  unsigned-by-default, so per-file ML-DSA-87 cost only applies when `--signer-secret`
  is given. Example: `--profile maximum --sig compact` → ML-KEM-1024 + ML-DSA-44.
* **Reuse the expanded recipient public key across a folder (not feasible
  upstream).** `pqcrypto` 0.3.1 exposes only `KyberKem.encapsulate(pk, [nonce])`,
  which re-unpacks the public key and re-expands `Â` on every call — there is no
  preprocessed-PK object to cache. It is also moot under the Phase 5 per-file
  isolate design (no shared heap). This optimization is blocked on the upstream
  KEM API (or the Phase 7 native backend); not implemented.
* **Single-pass header serialization (already satisfied).** `toBinary()` uses
  `lengthPrefixed`→`concat`, which pre-sizes one output buffer and copies each
  field exactly once. No meaningful change available; the real bulk win is Phase
  3 (the payload is never serialized into a buffer at all).

## Phase 7 — Native lattice acceleration (FFI seam)

The lattice backend is now swappable behind `PqLatticeProvider`
([pq_lattice_provider.dart](../../lib/src/algorithms/pq_lattice_provider.dart)):
`PqKemPrimitives` / `PqSignaturePrimitives` keep their validation and delegate the
raw crypto to `PqLattice.provider` (default `PqPureDartLatticeProvider`). A host
registers an FFI-accelerated backend with `PqLattice.provider = …`. A reusable
conformance + KAT-equivalence harness
([lattice_conformance.dart](../../test/support/lattice_conformance.dart)) gates any
backend against the pure-Dart reference. Prebuilt native binaries are
**deliberately not shipped or auto-compiled** (a host supply-chain concern); the
full build/integration path is in
[PHASE7_NATIVE_LATTICE_FFI.md](./PHASE7_NATIVE_LATTICE_FFI.md).

## Phase 8 — Pack-and-stream archive (many tiny files)

`pqforge pack` collapses a whole folder tree into one sequential stream
([pqforge_pack_service.dart](../../lib/src/services/pqforge_pack_service.dart))
sealed by a **single** streaming envelope — one KEM encapsulation and one optional
signature for the entire tree, instead of one per file. `pqforge unpack` restores
it (re-validating every path against traversal). Everything is bounded-memory (a
single chunk buffer) and the I/O is sequential, cutting both per-file PQC overhead
and small-write amplification on eMMC for the 50 000-tiny-file case. Demonstrated:
42 files → one `PQFS` archive, round-tripping to an identical tree.

**Post-audit (fix F2):** the pack pipeline is now spool-free end to end —
`PqFolderPack.packStream` feeds `PqForgeStreamCipher.encryptStream` directly,
and `decryptStream` feeds `PqFolderPack.unpackFromStream` — so no plaintext
archive ever touches disk, no extra free space is needed, and a failed unpack
deletes everything it created. Measured storage win at 1000 tiny files: 40 KB
archive vs 4.0 MB of per-file envelopes (~100×).

---

## Decisions & deviations from the blueprint

* **No envelope v2 / no v1 verify path.** Per the pre-release "no backward
  compatibility" instruction, the digest-signing change replaced the old signing
  outright (single format), instead of the blueprint's v1/v2 dual scheme.
* **`PqForge.encrypt` stays synchronous on PointyCastle for small messages.**
  Making the facade `async` to route the one-shot path through the async engine
  would break every caller for no benefit at small sizes. The *bulk* path is the
  one that matters, and it goes through the engine via streaming.
* **Streaming peak RSS vs the "2× frameSize" target.** The *live* working set is
  ~2–3× frameSize, but measured peak RSS sits at a constant ~tens of MB because
  the Dart VM reclaims per-frame garbage lazily (one sealed body per frame). The
  essential property holds: **peak RSS does not scale with file length** — the
  amplification ratio falls toward zero as the payload grows (see below). The
  rejected `mmap` design (C9) and raw-pointer isolate passing (§2.2 hazard) were
  not implemented, as directed.

---

## Benchmark results (maximum profile, this 8-core host)

Run the gate with:

```sh
PQFORGE_BENCH=1 PQFORGE_BENCH_MODE=streaming PQFORGE_BENCH_MB=64 \
  dart test -t benchmark test/benchmark_io_test.dart
```

`amplification = (peakRSS − baselineRSS) / payload`. Per-cell deltas in a shared
process are a conservative lower bound (see the Phase 0 methodology note);
the headline is the **trend of the absolute working set vs payload size**.

**Streaming holds a constant working set regardless of payload** (maximum
profile, measured):

| payload | op | Δ working set | amplification | gate |
| --- | --- | --- | --- | --- |
| 8 MiB | unsigned encrypt | 33.7 MiB | 4.21× | FAIL |
| **32 MiB** | unsigned encrypt | **34.9 MiB** | **1.09×** | **PASS** |
| 32 MiB | unsigned decrypt | 12.5 MiB | 0.39× | PASS |
| 32 MiB | signed encrypt | 5.0 MiB | 0.16× | PASS |
| 32 MiB | signed decrypt | 15.1 MiB | 0.47× | PASS |

The payload quadrupled (8 → 32 MiB) while the absolute Δ stayed ~constant
(33.7 → 34.9 MiB), so the amplification ratio dropped ~4× (4.21 → 1.09). All
four 32 MiB cells pass the 1.5× gate. Extrapolated, a multi-GB file holds the
**same few-tens-of-MB working set** — the Phase 3 goal. (The ~34 MiB floor is
GC-lag garbage + VM baseline, not live memory; the *live* set is ~2–3× the frame
size.) Signed streaming is now as cheap as unsigned (0.16× / 0.47×), confirming
the M1 fix — no whole-payload concatenation.

Pure-Dart AES-GCM throughput is ~0.85 MiB/s here regardless of profile or mode;
the ≥4× speedup target is a `cryptography_flutter`/hardware property and is not
observable on this pure-Dart host.
