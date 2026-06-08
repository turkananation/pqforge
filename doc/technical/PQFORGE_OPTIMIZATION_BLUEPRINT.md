# TECHNICAL ARCHITECTURE & OPTIMIZATION BLUEPRINT: COMPREHENSIVE REFACTORING OF PQFORGE FOR RESOURCE-CONSTRAINED ENVIRONMENTS

**From:** Turkana Nation

**Status:** Mandatory Production Engineering Refactoring Mandate — **vetted against source `2026-06-08`**

**Implementation Version:** v.0.1.2 (ruthless vetting pass)

---

## 0. VETTING VERDICT & EVIDENCE LEDGER

This revision is a **ground-truth correction** of the v0.1.1 mandate. The original
diagnosis was directionally useful in two places (chunked streaming; isolate
offload) but **factually wrong in its single most expensive prescription** and
**silent on the worst defect actually in the tree**. Before any engineering
starts, the team must internalise what the code really does — not what the prose
imagined.

### 0.1 The three corrections that change the whole plan

1. **There is no FFI bridge to optimise. `pqcrypto` 0.3.1 is 100% pure Dart on
   PointyCastle.** The v0.1.1 "Native Bridging (FFI) & Marshalling Overhead"
   section critiques a Dart↔C boundary **that does not exist anywhere in the
   dependency graph** (`grep -r dart:ffi` over `pqcrypto`, `pqforge`,
   `pointycastle`, `cryptography` → zero hits). The real lattice bottleneck is
   the **opposite** of marshalling: ML-KEM-1024 / ML-DSA-87 run as scalar,
   non-SIMD, pure-Dart NTT arithmetic. FFI is the *cure* the old doc mislabelled
   as the *disease*. **This inverts Section 3 entirely.**

2. **The worst large-file defect is undiagnosed: signed envelopes ML-DSA-sign
   the entire ciphertext, not a digest.** `PqForge.encrypt`
   ([lib/src/services/pqforge_service.dart:159](../../lib/src/services/pqforge_service.dart#L159))
   feeds `envelopeSigningMessage(unsigned)`
   ([:1144](../../lib/src/services/pqforge_service.dart#L1144)) — which
   `lengthPrefixed`-concatenates the full `payload` into a fresh buffer — into
   `sign(..., preHash: false)`. A signed 1 GB media seal therefore allocates a
   **second** gigabyte buffer and streams a gigabyte through pure-Dart SHAKE-256.
   v0.1.1 never mentions this. It is the headline fix.

3. **A faster AEAD engine already exists in-tree but is wired to the wrong path.**
   `PqForgeCryptographyAeadEngine` + `PqForgeSecureSession` exist, but
   `PqForge.encrypt` / `encryptFileBytes` / `sealMedia` / `encryptFolderEntry`
   **hardwire** `PqSymmetricPrimitives.aesGcmEncrypt` → PointyCastle pure-Dart GCM
   ([pqforge_service.dart:135](../../lib/src/services/pqforge_service.dart#L135)).
   The file/media/folder paths *never touch the swappable engine*. There is no
   "fallback to PointyCastle" — the bulk path is **unconditionally** PointyCastle.

### 0.2 Evidence Ledger — every v0.1.1 claim, adjudicated

| # | v0.1.1 Claim | Verdict | Ground truth (file:line) |
| --- | --- | --- | --- |
| C1 | `pqcrypto` has FFI marshalling overhead | **FALSE** | `pqcrypto` 0.3.1 is pure Dart on `pointycastle`; zero `dart:ffi` in the tree |
| C2 | Symmetric ops "drop back to PointyCastle" when native is absent | **FALSE** | Envelope path is *always* PointyCastle ([service:135](../../lib/src/services/pqforge_service.dart#L135)); native engine only reachable via `PqForgeSecureSession` |
| C3 | `package:cryptography` already uses ARM Neon / Apple crypto ext | **FALSE (today)** | `Cryptography.defaultInstance = BrowserCryptography.defaultInstance` → pure Dart on VM/mobile. HW accel needs `cryptography_flutter` + `FlutterCryptography.enable()` — **neither present** |
| C4 | CLI uses `final files = await _listFiles(inputDir)` | **FABRICATED** | No `_listFiles`. Real: `listFiles()` ([support:218](../../bin/src/support.dart#L218)) drains a `Stream` into a sorted `List`; loop at [pqc_commands:458](../../bin/src/pqc_commands.dart#L458) |
| C5 | `lengthPrefixed` "24 allocations" cause the 3 GB blow-up | **MISLEADING** | The 24 are tiny `uint32(4)` headers ([primitives:56](../../lib/src/primitives/pq_primitives.dart#L56)). The real blow-up is **full-payload copies** (see M-series) |
| C6 | `toBinary()` JSON metadata strains the GC at scale | **TRUE but minor** | `jsonEncode(metadata)` at [envelope:68](../../lib/src/codecs/pq_envelope.dart#L68); negligible vs payload, real only for many tiny folder files |
| C7 | Chunked per-block-AEAD streaming is required | **TRUE — keep** | No streaming exists; whole-file one-shot GCM only |
| C8 | Random per-block IVs are unsafe; derive deterministically | **TRUE, wrong reason** | Risk at 1 MB blocks/per-file key is truncation/reorder + the 2³² ceiling, *not* the birthday bound; and `IV ⊕ seq` is a weaker idiom than `salt‖counter` |
| C9 | mmap + in-place stream cipher for file I/O | **REJECT — unsafe & self-contradictory** | Unauthenticated (contradicts §1), AEAD output > input so in-place is impossible, no crash atomicity, non-portable to iOS |
| C10 | Apple AMX / crypto-ext SIMD accelerate Kyber/Dilithium math | **FALSE** | AMX is private/undocumented; ARMv8 Crypto Ext accelerates **AES/SHA**, not lattice NTT (that's generic NEON, a different unit) |
| C11 | `maximum` (1024/87) is the default for big files | **TRUE — strong point** | `encryptFileBytes`/`sealMedia`/`encryptFolderEntry` default `PqForgeProfile.maximum` ([service:327](../../lib/src/services/pqforge_service.dart#L327),[:598](../../lib/src/services/pqforge_service.dart#L598),[:733](../../lib/src/services/pqforge_service.dart#L733)); CLI `--profile` defaults `maximum` ([support:36](../../bin/src/support.dart#L36)) |
| C12 | ML-KEM-1024 = 4×4 matrix, ~77% more than 768's 3×3 | **HALF-TRUE** | k: 768→3, 1024→4; matrix entries 9→16 = +78% *for the matmul step only*. End-to-end encaps is ~1.3–1.6×, not a flat 77% |

### 0.3 Defects v0.1.1 missed (the real backlog)

| # | Defect | Evidence | Cost on 1 GB |
| --- | --- | --- | --- |
| M1 | Signed envelope signs the **whole ciphertext** | [service:159](../../lib/src/services/pqforge_service.dart#L159)+[:1144](../../lib/src/services/pqforge_service.dart#L1144), `preHash:false` | +1 GB buffer + 1 GB through pure-Dart SHAKE |
| M2 | `Uint8List.fromList(await f.readAsBytes())` everywhere | [pqc_commands:288](../../bin/src/pqc_commands.dart#L288),[:461](../../bin/src/pqc_commands.dart#L461),[:795](../../bin/src/pqc_commands.dart#L795),[:975](../../bin/src/pqc_commands.dart#L975); [support:170](../../bin/src/support.dart#L170) | redundant full-file copy (`readAsBytes` already returns `Uint8List`) |
| M3 | `PqEnvelope` ctor deep-copies `payload`; signed path builds envelope **twice** | [envelope:23-25](../../lib/src/codecs/pq_envelope.dart#L23) | 2× payload copies in ctor + 1× in `concat` |
| M4 | Entire pipeline synchronous on caller isolate | [service:113](../../lib/src/services/pqforge_service.dart#L113) | multi-second main-isolate stall → ANR/jank |
| M5 | One-shot GCM tag ⇒ decrypt also needs whole file in RAM; no streaming verify; 64 GiB AES-GCM ceiling | [service:314](../../lib/src/services/pqforge_service.dart#L314) | OOM on **decrypt** too; >64 GiB impossible |

**Peak resident for a signed 1 GB seal today ≈ 4–5× payload:** input (M2 doubles it) → GCM output → unsigned-envelope copy (M3) → signing-message concat (M1) → signed-envelope copy (M3). The "3 GB for 1 GB" figure in v0.1.1 *under*-counts the signed path and blames the wrong line.

### 0.4 What the code already does well (do not regress)

The defensive copies (M3), `constantTimeEquals`
([primitives:76](../../lib/src/primitives/pq_primitives.dart#L76)), key
zeroization on `dispose`/failure
([secure_session:142](../../lib/src/cipher/pq_secure_session.dart#L142),
[pointycastle_engine:113](../../lib/src/cipher/pq_pointycastle_aead_engine.dart#L113)),
and the zero-copy `Uint8List.sublistView` decrypt views
([secure_session:131](../../lib/src/cipher/pq_secure_session.dart#L131)) are
**deliberate misuse-resistance**, not waste. The fix is to add a *streaming path*
that bypasses whole-payload materialisation — **not** to strip safety from the
existing small-message path.

---

## 1. GIGABYTE-SCALE MEMORY MANAGEMENT & CHUNKED AEAD STREAMING

### 1.1 The real ingestion path (corrected)

Every bulk entry point funnels into one synchronous method:

```
CLI encrypt/-media/-folder ─▶ sealMedia / encryptFolderEntry / encrypt
                                   └─▶ PqForge.encrypt  (service:113)
                                         ├─ PqKemPrimitives.encapsulate   (KEM, fixed cost)
                                         ├─ _kemDemKey  → HKDF-SHA256       (fixed cost)
                                         ├─ aesGcmEncrypt(WHOLE plaintext)  (PointyCastle, pure Dart)  ← copy #1 (ct)
                                         ├─ PqEnvelope(...)  payload=copy() (envelope:24)              ← copy #2
                                         ├─ [signed] envelopeSigningMessage → concat(payload)          ← copy #3
                                         ├─ [signed] ML-DSA.sign(whole msg, preHash:false)             ← 1 GB hash
                                         └─ [signed] PqEnvelope(...) again  payload=copy()              ← copy #4
        writeEnvelope ─▶ toBinary() ─▶ lengthPrefixed ─▶ concat(payload)                               ← copy #5
```

The contiguous `Uint8List` requirement is real, but the OOM driver is **payload
copy multiplicity (M1–M3, M5)**, not the 24 length-prefix headers (C5).

### 1.2 Target: bounded-memory streaming AEAD (≤ a few MB resident)

Because an AEAD tag only protects fully-processed data, we keep v0.1.1's correct
core: a master header followed by a sequence of **independently authenticated
frames**. This is the proven libsodium `secretstream` / Tink Streaming-AEAD / age
construction.

```text
+==================== pqforge streaming envelope (.pqfs) ====================+
| MasterHeader: magic"PQFS" | ver | profile | kemAlg | sigAlg              |
|              | KEM ciphertext | nonceSalt(4B) | frameSize(4B) | meta     |
|              | headerSig? (ML-DSA over H(header), preHash) ── O(1) in N   |
+---------------------------------------------------------------------------+
| Frame[i] (i = 0..n-1):  len(4B) | seq(8B) | ciphertext(≤frameSize) | tag(16B) |
|   key   = per-file DEM key (HKDF, already derived once)                   |
|   nonce = nonceSalt(4B) ‖ uint64(seq)            (unique under per-file key)|
|   aad   = H(MasterHeader) ‖ uint64(seq) ‖ uint8(isFinal)                   |
+===========================================================================+
```

Why this framing:

- **Per-file fresh DEM key** is already produced by `_kemDemKey`
  ([service:1160](../../lib/src/services/pqforge_service.dart#L1160)); a 4-byte
  salt + 8-byte counter nonce is collision-free under it. This fixes C8 *without*
  the fragile `IV ⊕ seq` idiom — and without invoking the (irrelevant at 1 MB
  blocks) birthday argument.
- **`seq` + `isFinal` bound into AAD** make truncation, reordering, duplication,
  and splicing forgeable-proof. This is the part v0.1.1 got right; keep it.
- **Header signed over `H(header)` with `preHash:true`** makes signature cost
  independent of file size (fixes M1).

### 1.3 Reference writer (no FFI, no mmap, reuses existing engine)

Slots onto the existing `PqForgeAeadEngine` contract
([pq_cipher_suite.dart:104](../../lib/src/cipher/pq_cipher_suite.dart#L104)):

```dart
/// Streams plaintext from `source` to `sink` as authenticated frames.
/// Peak heap ≈ 2 × frameSize, independent of file length.
Future<void> writeStreamingEnvelope({
  required RandomAccessFile source,
  required IOSink sink,
  required PqForgeAeadEngine engine,   // pure-Dart OR cryptography_flutter
  required Uint8List demKey,           // from _kemDemKey, per file
  required Uint8List masterHeader,     // already serialized (KEM ct + meta)
  int frameSize = 1 << 20,             // 1 MiB
}) async {
  sink.add(masterHeader);
  final headerHash = PqBytes.sha256(masterHeader);
  final nonceSalt = PqBytes.randomBytes(4);
  final buf = Uint8List(frameSize);              // ONE reused read buffer
  final total = await source.length();
  var seq = 0, read = 0;

  while (read < total) {
    final n = await source.readInto(buf);        // zero extra copy; fills `buf`
    if (n <= 0) break;
    final isFinal = (read + n) >= total;
    final view = Uint8List.sublistView(buf, 0, n); // view, not copy
    final nonce = Uint8List(12)
      ..setRange(0, 4, nonceSalt)
      ..buffer.asByteData().setUint64(4, seq, Endian.big);
    final aad = Uint8List(headerHash.length + 9)
      ..setRange(0, headerHash.length, headerHash)
      ..buffer.asByteData().setUint64(headerHash.length, seq, Endian.big)
      ..[headerHash.length + 8] = isFinal ? 1 : 0;
    final body = await engine.seal(             // ciphertext‖tag
        key: demKey, nonce: nonce, plaintext: view, aad: aad);
    final frameHdr = Uint8List(12)
      ..buffer.asByteData().setUint32(0, body.length, Endian.big)
      ..buffer.asByteData().setUint64(4, seq, Endian.big);
    sink..add(frameHdr)..add(body);
    read += n; seq++;
  }
  await sink.flush();
}
```

Decrypt is the mirror: read 12-byte frame header, read `len` bytes, verify with
the reconstructed AAD, **release plaintext frame-by-frame** (fixes M5 on the
decrypt side — the receiver never holds the whole file either).

### 1.4 Eliminate the copies on the small-message path too (cheap wins now)

- **M2:** delete every `Uint8List.fromList(await file.readAsBytes())` →
  `await file.readAsBytes()` already returns a `Uint8List`. Mechanical, safe.
- **M1:** change envelope signing to sign `H(headerFields ‖ H(ciphertext))` with
  `preHash:true`. Backward-incompatible on the wire ⇒ gate behind envelope
  `version: 2`.
- **M3:** for the *streaming* path, never build a `PqEnvelope` value object around
  the payload at all — write header then frames straight to the sink. Keep the
  value-object + defensive copies only for the legacy small-message API.

---

## 2. MULTI-CORE PARALLELISM & DART ISOLATES

### 2.1 Corrected problem statement

The pipeline is fully synchronous (M4): on Flutter, encrypting one large file
blocks the UI isolate for seconds. That is the real latency bug — *not* a lack of
N-core fan-out. **Fix the offload before the fan-out.**

### 2.2 De-scope the v0.1.1 isolate design

v0.1.1's "raw `Pointer<Uint8>` address passed across isolates as an int" scheme is
**rejected**: it hands unmanaged memory across isolate boundaries with no
ownership, no finalizer, and a manual `calloc.free` on a *different* isolate than
the allocator — a classic use-after-free / double-free generator, and pointless
because the AEAD path needs no native buffer transport. Use the right tool for
each axis:

**Axis A — keep the event loop alive (always do this):** wrap the bulk operation
in `Isolate.run`. One call, structured, auto-disposed:

```dart
final envelopeBytes = await Isolate.run(() => _encryptFileSync(args));
```

**Axis B — folder concurrency (the common case): one file per isolate, bounded
pool.** Far simpler than intra-file chunk fan-out, and it sidesteps every
shared-nonce hazard because each isolate owns a *distinct file with its own DEM
key*:

```dart
Future<void> encryptFolderParallel(List<File> files, EncryptArgs base) async {
  final pool = Semaphore(Platform.numberOfProcessors.clamp(1, 4));
  await Future.wait(files.map((f) async {
    await pool.acquire();
    try {
      // TransferableTypedData = zero-copy move across the boundary (C-correct,
      // unlike raw pointer-int passing). Sender loses the bytes; no deep copy.
      final out = await Isolate.run(() => _encryptOneSync(f.path, base));
      await File('${f.path}.pqf').writeAsBytes(out);
    } finally { pool.release(); }
  }));
}
```

**Axis C — intra-file chunk fan-out (only if a single file dominates AND the
cipher is pure-Dart).** If AES runs on AES-NI/ARMv8 (via `cryptography_flutter`,
§3) a single core already does multiple GB/s and fan-out is wasted parallelism +
nonce-management risk. Reach for it **last**, and if you do: the orchestrator owns
the per-file DEM key + `nonceSalt`; workers receive `(seq, frameBytes)` via
`TransferableTypedData`, return `(seq, body)`; the orchestrator writes frames in
`seq` order. Counter nonces (§1.2) make this safe; never `PqBytes.randomBytes` per
worker (the one v0.1.1 instinct worth keeping).

### 2.3 Decision rule

```
single small file        → synchronous (no isolate; overhead > work)
single large file        → Axis A (Isolate.run) ; add Axis C only if pure-Dart cipher
folder / many files      → Axis B (per-file pool)  ← the gigabyte-folder workhorse
```

---

## 3. NATIVE ACCELERATION — THE INVERTED SECTION

> v0.1.1 told you to *remove* FFI marshalling overhead. **There is no FFI.** The
> task is the reverse: *introduce* native acceleration where today there is
> none.

### 3.1 Two independent acceleration problems

| Layer | Today | Native path |
| --- | --- | --- |
| **Bulk symmetric** (AES-GCM / ChaCha20-Poly1305) | pure-Dart PointyCastle on the envelope path (C2) | `cryptography_flutter` → CryptoKit (iOS/macOS) / `javax.crypto`+Conscrypt (Android) → **AES-NI / ARMv8 AESE/PMULL** |
| **Lattice** (ML-KEM-1024 / ML-DSA-87) | pure-Dart scalar NTT in `pqcrypto` | FFI to a vetted C lib (PQClean / liboqs / mlkem-native) compiled with **NEON / AVX2** |

These are decoupled. Do the symmetric one first — it's an afternoon and it
accelerates the gigabyte payload, which is where the bytes are.

### 3.2 Symmetric acceleration (low effort, high yield) — wire the engine that already exists

The envelope path must stop calling `PqSymmetricPrimitives.aesGcmEncrypt`
directly and go through the swappable `PqForgeAeadEngine`. Then enable hardware
backing app-side:

```yaml
# pubspec.yaml
dependencies:
  cryptography_flutter: ^2.3.0   # registers OS-native AES-GCM/ChaCha implementations
```

```dart
// main() of the host app, before any crypto:
FlutterCryptography.enable();   // Cryptography.instance = FlutterCryptography()
```

With this, `crypto.AesGcm.with256bits()` inside
[pq_cryptography_aead_engine.dart:20](../../lib/src/cipher/pq_cryptography_aead_engine.dart#L20)
dispatches to AES-NI/ARMv8 and runs **off the Dart thread**. Pair it with the §1
streaming writer and the gigabyte path is solved without writing a line of C.
ChaCha20-Poly1305 remains the right default on CPUs without AES instructions
(already a suite, [pq_cipher_suite.dart:24](../../lib/src/cipher/pq_cipher_suite.dart#L24)).

### 3.3 Lattice acceleration (higher effort) — FFI to a static C library

Pure-Dart Kyber/Dilithium is the lattice throughput wall. For embedded targets
that sign/encapsulate per file in tight folder loops, bind a vetted C
implementation behind the existing `PqKemPrimitives` / `PqSignaturePrimitives`
seam (so the Dart API is unchanged):

- **Source:** PQClean or `mlkem-native` / liboqs — ship as a prebuilt static
  archive per ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`, Apple `arm64`).
- **Build:** `-O3 -mcpu=native`/`-march=armv8-a+crypto`; the AVX2/NEON optimised
  variants exist upstream — *that* is the NEON win, on the NTT, not on AES.
- **Bridge:** `DynamicLibrary.open` on Android, `DynamicLibrary.process()` on iOS
  (statically linked into the runner). Marshal keys once into native scratch
  (`malloc` + `asTypedList().setAll`), call, copy results back, `free`. Keep
  buffers small — ML-KEM ct is 1568 B, ML-DSA-87 sig is 4627 B
  ([pq_algorithms.dart:37](../../lib/src/algorithms/pq_algorithms.dart#L37),[:90](../../lib/src/algorithms/pq_algorithms.dart#L90))
  — so marshalling cost is *noise* (this is why C1's "marshalling overhead" was
  always a non-issue even hypothetically).

### 3.4 Hardware reality check (corrects C10)

- **ARMv8 Cryptography Extension** (`AESE/AESD/AESMC/PMULL`) → accelerates **AES**
  and GHASH, i.e. the AEAD layer. Reached via `cryptography_flutter`, §3.2.
- **Generic NEON SIMD** → accelerates **Kyber/Dilithium NTT** (butterflies,
  Montgomery reduction). Reached via the C lib, §3.3. *Different execution unit
  from the crypto extension.*
- **Apple AMX** → **private, undocumented, not targetable** from a portable static
  lib. The public Apple path is the NEON units / Accelerate; do not design around
  AMX.
- **Poly1305** is a one-time MAC, not "hashing"; no dedicated ARM instruction —
  it rides NEON `UMULL` 64×64→128. Drop the "Poly1305 hashing instructions"
  framing.

---

## 4. ALGORITHMIC & CRYPTO SURFACE TUNING

### 4.1 The `maximum`-by-default problem is real and precisely located (C11)

Bulk paths default to **ML-KEM-1024 / ML-DSA-87**
([service:327](../../lib/src/services/pqforge_service.dart#L327),[:598](../../lib/src/services/pqforge_service.dart#L598),[:733](../../lib/src/services/pqforge_service.dart#L733);
[support:36](../../bin/src/support.dart#L36)). But size the cost correctly:

- KEM/DEM/signature cost is **fixed per file** (~1568 B ct + ~4627 B sig +
  constant compute), *independent of payload size*. At 1 GB it is **rounding
  error**. At a folder of 50 000 tiny files it is the **dominant** cost
  (50 000 × ML-DSA-87 signs + 50 000 × Kyber-1024 encaps, all pure-Dart, all
  synchronous).
- So "maximum profile" is a **small-file / folder** problem, *not* a gigabyte
  problem. Reframe the optimisation accordingly.

### 4.2 Correct the matrix-cost claim (C12)

`k`: 512→2, 768→3, 1024→4. Matrix `Â` has `k²` entries → 9 vs 16 = **+78% for the
matmul step only**. End-to-end encaps/decaps also carries `k`-linear work
(vector NTTs, CBD sampling) and fixed hashing, so measured 1024-vs-768 is
typically **~1.3–1.6×**, not a flat 77% applied to everything. ML-DSA-87
`(k,l)=(8,7)` expands `Â` to ~43 KB > 32 KB L1D — the "exceeds L1" remark is fair,
but state it as the expanded-matrix working set, and note signing is
**rejection-sampled ⇒ variable iteration count** (a real latency-jitter source on
embedded chips, worth flagging that the *compute is non-constant-time in
iterations* — fine for signing, never gate UI on its worst case).

### 4.3 Genuine micro-optimisations (grounded)

1. **Profile-by-purpose.** Bulk file/media bytes are protected by the AEAD under
   a 256-bit key regardless of KEM strength; the KEM only protects that key.
   Offer `--kem maximum --sig balanced` or default folder mode to a lighter
   signature unless `--sign` is requested. Decouple payload risk from per-file
   PQC overhead.
2. **Reuse the expanded recipient key across a folder.** In `encrypt-folder` the
   recipient public key is constant across thousands of entries. Expand `Â` /
   unpack the public key **once** and reuse it for every encapsulation instead of
   re-deriving per call. This is the legitimate core of v0.1.1's "NTT caching" —
   bounded to where it actually pays (one recipient, N files), not a speculative
   global cache.
3. **Ephemeral KEM/keygen pool** only helps *keygen*-bound flows (hybrid
   handshakes generating fresh ephemerals), not the recipient-encaps flow.
   Keep it for the hybrid session layer
   ([pq_classical_hybrid.dart](../../lib/src/hybrid/pq_classical_hybrid.dart)),
   not for file encryption where you encapsulate to a *given* PK.
4. **Single-pass envelope serialization** (valid, scoped): pre-size and write at
   offsets in `toBinary()` for the **header/small-message** path. For bulk, the
   real win is §1 — *don't serialize the payload into a buffer at all*. Don't let
   "one big `Uint8List`" smuggle the whole file back into RAM.

---

## 5. EMBEDDED & MOBILE FILE I/O

### 5.1 Reject the mmap design (C9) — it is unsafe and non-portable

`processFileMmapInPlace` + `_applyInPlaceStreamCipher` must not ship:

1. It is **unauthenticated** in-place stream-ciphering — directly contradicting
   §1's correct "no unauthenticated streaming" rule.
2. **AEAD output > input** (per-frame tag + headers). You *cannot* authenticate
   in place over a region of exactly `fileLength`. The geometry is impossible.
3. **No crash atomicity:** `MAP_SHARED` in-place mutation destroys plaintext as it
   goes; power loss mid-run = unrecoverable file, tag never written. For a
   sealing tool this is data loss masquerading as speed.
4. **Not portable:** `dlopen("libc.so.6")` is Linux/Android-NDK; iOS forbids it
   and the mmap symbol/flag surface differs. Wrong primitive for a cross-platform
   mobile library.

### 5.2 The actual I/O bug and its portable fix

The real cost is **whole-file `readAsBytes` materialisation** (a 1 GB Dart-heap
allocation), not syscall count. The `directory.list(recursive:true)` enumeration
([support:218](../../bin/src/support.dart#L218)) is already a `Stream`; the only
issue is it's eagerly drained to a sorted `List` before any work begins (latency
- holds every `File`/path for a 100k-file tree).

Concrete, no-FFI fixes:

- **Frame reads** with `RandomAccessFile.readInto(reusedBuffer)` (§1.3) or
  `file.openRead(start, end)` `Stream<List<int>>`. Peak heap = one frame, not the
  file. This is the portable equivalent of everything mmap was reaching for.
- **Pipeline the walk:** consume `directory.list(...)` as a stream feeding the
  bounded per-file isolate pool (§2.2-B); sort only if deterministic output
  ordering is a requirement (today it sorts for stable output — make it
  optional/opt-in for huge trees).
- **Write with one buffered `IOSink`** per output file; `add()` header then
  frames; one `flush()`. No per-frame `open/close`.
- **Optional, orthogonal:** TAR-pack many tiny files into one sequential stream to
  cut write amplification on eMMC. Useful, but it adds a container format and is
  independent of the crypto fixes — schedule it after, not in, the core work.

---

## 6. SEQUENCED IMPLEMENTATION PLAN & ACCEPTANCE METRICS

Ordered by **(impact ÷ effort)**, each phase independently shippable and testable.

```
PHASE 0 — Truth & guardrails (0.5 day)
  • Add a 1 GB synthetic-file bench (encrypt+decrypt, signed+unsigned, each profile)
    capturing peak RSS + wall time. This is the regression gate for every phase.
  • Acceptance: baseline numbers recorded; CI fails build if peak RSS > 1.5× file size.

PHASE 1 — Kill the gratuitous copies (0.5 day, no wire change)
  • M2: drop every Uint8List.fromList(readAsBytes()).            [pqc_commands, support]
  • M3: streaming path bypasses PqEnvelope value object.
  • Acceptance: peak RSS for UNSIGNED 1 GB seal drops from ~3× → ~2× file size.

PHASE 2 — Sign the digest, not the file (1 day, envelope v2)
  • M1: envelopeSigningMessage → sign H(header ‖ H(ciphertext)), preHash:true.
        Gate behind envelope version:2; keep v1 verify for back-compat.
  • Acceptance: signed-seal time becomes ~independent of file size; peak RSS for
    SIGNED 1 GB seal drops from ~5× → ~2× file size.

PHASE 3 — Streaming AEAD frame format (3–5 days, new .pqfs) ............... CORE
  • Implement writeStreamingEnvelope / readStreamingEnvelope (§1.3) on the
    existing PqForgeAeadEngine seam; salt‖counter nonce; seq+isFinal in AAD.
  • Route CLI encrypt/-media/-folder + sealMedia/encryptFolderEntry through it
    for inputs over a threshold (e.g. >8 MiB); small inputs keep legacy envelope.
  • Acceptance: peak RSS ≈ 2 × frameSize (a few MB) for ANY file size, encrypt
    AND decrypt; a >64 GiB file encrypts/decrypts/round-trips on a 2 GB-RAM device.

PHASE 4 — Wire the fast symmetric engine + offload (1–2 days)
  • Route envelope/streaming AEAD through PqForgeAeadEngine (not the direct
    PqSymmetricPrimitives call). Document cryptography_flutter + FlutterCryptography.enable()
    for host apps. Wrap bulk ops in Isolate.run (Axis A).
  • Acceptance: main-isolate stall for a 1 GB seal < 16 ms (one frame budget);
    AES-GCM throughput ≥ 4× the PointyCastle baseline on an AES-NI/ARMv8 device.

PHASE 5 — Folder concurrency (1–2 days)
  • Bounded per-file isolate pool (Axis B); stream the directory walk into it.
  • Acceptance: folder of N files scales ~linearly to min(N, cores); no nonce/key
    sharing across isolates (one DEM key per file, by construction).

PHASE 6 — Algorithmic tuning (2–3 days)
  • Decouple KEM vs signature profile; reuse expanded recipient PK across a folder;
    single-pass header serialization.
  • Acceptance: 50 000-tiny-file folder seal time drops measurably; recipient-PK
    expansion happens once per folder, verified by counter/trace.

PHASE 7 — (Optional) Lattice FFI (1–2 weeks)
  • Bind PQClean/liboqs static libs behind PqKemPrimitives/PqSignaturePrimitives;
    per-ABI prebuilt archives; fall back to pure-Dart pqcrypto when absent.
  • Acceptance: per-op ML-KEM-1024 encaps / ML-DSA-87 sign ≥ 5× faster than
    pure-Dart on arm64; identical KATs vs pure-Dart (interop preserved).

PHASE 8 — (Optional) TAR pre-pack for many-small-files write amplification.
```

### 6.1 Refactor target matrix (corrected from v0.1.1)

```
[ lib/src/services/pqforge_service.dart ]
  -> M1: sign H(header‖H(ct)), preHash:true (envelope v2). O(1)-in-N signatures.
  -> Route bulk through a streaming writer + PqForgeAeadEngine, not direct PointyCastle.

[ lib/src/codecs/pq_envelope.dart ]
  -> Add .pqfs streaming reader/writer; single-pass header serialization.
  -> Keep value-object + defensive copies for the SMALL-message path (do not regress).

[ lib/src/cipher/pq_secure_session.dart + the two AEAD engines ]
  -> Reuse the PqForgeAeadEngine seam as the streaming frame cipher.
  -> Engine choice (PointyCastle vs cryptography_flutter) becomes the HW-accel lever.

[ bin/src/pqc_commands.dart + bin/src/support.dart ]
  -> M2: remove Uint8List.fromList(readAsBytes()).
  -> RandomAccessFile.readInto framing; stream listFiles() into a bounded isolate pool.

[ pubspec.yaml (host app) ]
  -> Add cryptography_flutter; call FlutterCryptography.enable() at startup.
```

### 6.2 Rescinded v0.1.1 directives (do **not** implement)

- ❌ "Optimise the pqcrypto FFI marshalling boundary." — no FFI exists (C1).
- ❌ Raw `Pointer<Uint8>`-address passed across isolates as an int (§2.2 hazard).
- ❌ `mmap` + in-place unauthenticated stream cipher (C9 / §5.1).
- ❌ Designing around Apple AMX or "crypto-extension SIMD for lattice math" (C10).
- ❌ Treating `lengthPrefixed`'s 24 header allocations as the OOM cause (C5).

---

**Bottom line:** the gigabyte path is fixable with **zero C** — Phases 1–5 (kill
copies → sign the digest → frame-stream → native AES via `cryptography_flutter` →
per-file isolates) take `pqforge` from ~5× peak RSS and main-isolate stalls to a
constant few-MB working set with hardware-backed throughput. Native lattice FFI
(Phase 7) is a real, separate win for folder-of-many-files workloads, but it is an
*addition* of acceleration, not the removal of a marshalling tax that was never
there.
