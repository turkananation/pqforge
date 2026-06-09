# PHASE 0 — Synthetic Benchmarking Infrastructure & Recorded Baseline

**Status:** Implemented. This is the regression gate for every later phase of
[PQFORGE_OPTIMIZATION_BLUEPRINT.md](./PQFORGE_OPTIMIZATION_BLUEPRINT.md).

**Recorded:** 2026-06-09 · Dart 3.12.0 · linux_x64 · 8 cores · ~11 GiB RAM.

---

## 1. What was built

| Artifact | Purpose |
| --- | --- |
| [test/support/benchmark_harness.dart](../../test/support/benchmark_harness.dart) | Framework-free measurement library: `RssSampler` (50 ms `ProcessInfo.currentRss` polling), `measure()`, `MemoryBudget`/`BudgetVerdict` (the 1.5× gate), `BenchmarkResult`, `BenchmarkReport` (console table + JSON). |
| [test/benchmark_io_test.dart](../../test/benchmark_io_test.dart) | Two groups: a **fast budget-gate** unit group (always runs) and a **heavy synthetic-I/O** group (opt-in) that drives the real `PqForge.encrypt`/`decrypt` path. |
| [dart_test.yaml](../../dart_test.yaml) | Declares the `benchmark` tag (30 min timeout). |

### Why the workload runs inside `Isolate.run`

The production bulk pipeline is fully synchronous on the caller isolate
(defect **M4**). A same-isolate `Timer.periodic` sampler would be starved for the
entire encryption and miss the peak. The harness therefore samples
`ProcessInfo.currentRss` on the **parent** isolate while the work runs in an
`Isolate.run` **worker**. Because RSS is a process-wide OS metric, the worker's
allocations are visible to the parent's sampler (verified: a 300 MiB worker
allocation shows up as a ~289 MiB parent-side delta; `ProcessInfo.maxRss`
corroborates the sampled peak).

---

## 2. How to run

```sh
# Fast budget-gate unit tests only (this runs under a plain `dart test`):
dart test test/benchmark_io_test.dart

# Full memory-tracked baseline (slow — see §4):
PQFORGE_BENCH=1 dart test -t benchmark test/benchmark_io_test.dart
```

| Env var | Default | Meaning |
| --- | --- | --- |
| `PQFORGE_BENCH` | _unset_ | Set to `1` to run the heavy group. |
| `PQFORGE_BENCH_MB` | `8` | Payload size in MiB. Amplification is size-independent on the current whole-file path, so a small payload still proves the defect; scale up only on a big-RAM box. |
| `PQFORGE_BENCH_PROFILES` | `maximum` | Comma list of `compact,balanced,maximum`. |
| `PQFORGE_BENCH_ENFORCE` | _unset_ | Set to `1` to turn budget breaches into **test failures**. Leave **off** for the Phase 0 baseline (it is *expected* to exceed budget); flip **on** once the Phase 3 streaming path lands. |
| `PQFORGE_BENCH_REPORT` | system temp | JSON report output path. |

For the cleanest per-config numbers, run **one profile per invocation** (a fresh
process; see the methodology caveat in §5).

---

## 3. The two gate metrics

A single absolute "peak > 1.5× file size" rule (as literally written in the
blueprint) is only meaningful once the payload dwarfs the ~150–200 MiB Dart VM
floor. The harness therefore tracks **both**:

1. **Payload amplification** = `(peak − baseline) / payload` — the size-robust
   regression signal, and the basis of the PASS/FAIL gate (limit **1.5×**). A
   bounded streaming path drives this toward zero regardless of payload.
2. **Absolute peak factor** = `peak / payload` — the blueprint's literal rule,
   reported but only flagged *active* at/above 256 MiB payload (else
   *informational*).

The exit gate ("a peak > 1.5× must fail the check") is proven by the fast unit
group, independent of any heavy allocation.

---

## 4. Recorded baseline — 8 MiB payload, one profile per fresh process

Throughput is the pure-Dart PointyCastle AES-GCM rate; it is **profile-independent**
(same 256-bit key) and is the figure Phase 4 must beat by ≥4×.

| profile | signed | op | baseline | peak | Δ (peak−base) | **amplification** | MiB/s | gate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| compact | no | encrypt | 162.7 | 189.1 | 26.3 | **3.29×** | 0.84 | FAIL |
| compact | no | decrypt | 184.4 | 192.7 | 8.3 | 1.04× | 0.81 | PASS |
| compact | yes | encrypt | 192.3 | 213.7 | 21.3 | **2.67×** | 0.80 | FAIL |
| compact | yes | decrypt | 190.8 | 215.9 | 25.2 | **3.15×** | 0.80 | FAIL |
| balanced | no | encrypt | 160.0 | 189.0 | 29.0 | **3.62×** | 0.78 | FAIL |
| balanced | no | decrypt | 183.5 | 193.6 | 10.2 | 1.27× | 0.83 | PASS |
| balanced | yes | encrypt | 193.3 | 210.3 | 17.0 | **2.13×** | 0.78 | FAIL |
| balanced | yes | decrypt | 186.2 | 215.1 | 28.9 | **3.61×** | 0.82 | FAIL |
| maximum | no | encrypt | 207.0 | — | — | **3.26×** ¹ | 0.86 | FAIL |
| maximum | no | decrypt | — | — | — | 1.22× ¹ | 0.89 | PASS |
| maximum | yes | encrypt | 183.1 | 252.8 | 69.7 | **3.09–8.72×** ¹ | 0.82 | FAIL |
| maximum | yes | decrypt | 183.6 | 208.0 | 24.5 | **5.66×** ¹ | 0.82 | FAIL |

(MiB columns in MiB.) ¹ `maximum` headline figures are from the first dedicated
run; cross-cell residency makes per-cell deltas in combined runs a conservative
**lower bound** (see §5). The signed `maximum` encrypt was observed between
3.09× and 8.72× depending on inherited residency — i.e. the worst offender.

### Findings

- **Amplification matches the blueprint** (~3× unsigned encrypt, up to ~5.7×
  signed). It is **profile-independent**, confirming the driver is *payload-copy
  multiplicity* (defects **M1–M3, M5**), not KEM/signature size.
- **M1 also blows up signed *decrypt*** — not just encrypt as the blueprint
  framed it. Signature verification re-concatenates the **whole payload** through
  `envelopeSigningMessage`, so signed `decrypt` is the single worst peak
  (`maximum/signed/decrypt` ≈ 5.66×). Phase 2 (sign the digest) should improve
  **both** directions.
- **Unsigned decrypt already passes (~1.0–1.3×)** because `PqEnvelope.fromBinary`
  uses `sublistView` (zero-copy) — a "do not regress" datum.
- **Throughput is ~0.8 MiB/s**, profile-independent → a literal 1 GB run would
  take ~20 min/op and exceed this box's RAM; hence the 8 MiB default.
- The **absolute** 1.5×-peak gate is *informational* at 8 MiB (peak/payload ≈
  23–30× is all VM floor); it only becomes meaningful at ≥256 MiB payloads.

---

## 5. Methodology caveat (cross-cell baseline drift)

Within a single process, the OS lazily retains a prior (heavier) cell's pages, so
a later cell's *baseline* reading is inflated and `peak − baseline` can read as
low as `0.00×` even though the absolute peak is accurate. Consequences:

- Per-cell amplification in a **combined** multi-profile/​multi-sign run is a
  **conservative lower bound**, not an over-estimate.
- The **first cell** in each process (unsigned encrypt) is the cleanest reading.
- For authoritative numbers, run **one profile per invocation** (done for the
  table above). A future enhancement could fork a fresh subprocess per cell.

The `peakRssBytes` and `maxRssEndBytes` fields in the JSON report are always
accurate; only the baseline-relative *delta* is subject to this drift.

---

## 6. Exit gate — satisfied

- ✅ Synthetic payload generator (streamed, bounded setup memory) + 50 ms
  `ProcessInfo.currentRss` sampling; wall time, throughput, and peak amplification
  recorded to a diff-ready JSON report.
- ✅ The safety check is proven to **fail** a peak > 1.5× and **pass** a bounded
  one (fast unit group, always-on).
- ✅ Baseline numbers recorded above; current code fails the gate on **9 of 12**
  cells, quantifying the work for Phases 1–4. Enforcement (`PQFORGE_BENCH_ENFORCE=1`)
  is left off until streaming lands.
