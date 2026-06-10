# Phase 7 — Native Lattice Acceleration (FFI Seam)

Pure-Dart ML-KEM / ML-DSA (`pqcrypto`) runs as scalar NTT arithmetic — the
throughput wall when signing/encapsulating per file in tight folder loops. This
phase makes the lattice backend **swappable** so a host can register an
FFI-accelerated implementation, while the pure-Dart backend stays the default
and fallback.

## What ships in pqforge

| Artifact | Purpose |
| --- | --- |
| `PqLatticeProvider` ([pq_lattice_provider.dart](../../lib/src/algorithms/pq_lattice_provider.dart)) | The backend interface: raw `kem*` / `dsa*` operations. |
| `PqPureDartLatticeProvider` | Built-in default (wraps `pqcrypto`). Always present. |
| `PqLattice.provider` | Process-wide registry; assign a native backend at startup, `PqLattice.useDefault()` restores pure Dart. |
| `latticeProviderConformance` / `assertProvidersAgree` ([test/support/lattice_conformance.dart](../../test/support/lattice_conformance.dart)) | The contract + KAT-equivalence gate every backend must pass. |

`PqKemPrimitives` / `PqSignaturePrimitives` keep all length/validation checks and
delegate only the cryptography to `PqLattice.provider`, so **no caller changes**.

## What is deliberately *not* shipped

Prebuilt native binaries are **not** bundled or auto-compiled here. Fetching and
compiling external C (PQClean / liboqs) is a supply-chain action that belongs to
the host build, under the host's review and toolchains (Android NDK, Xcode,
per-ABI cross-compilers). pqforge ships the **seam and the equivalence gate**;
the binaries and FFI glue are a host integration step, below.

## Integrating a native backend

1. **Vendor a vetted C implementation** — PQClean (`crypto_kem/ml-kem-1024`,
   `crypto_sign/ml-dsa-87`, …) or liboqs, building the NEON (arm64) / AVX2
   (x86_64) optimised variants. *That* is where the SIMD win lives — on the NTT,
   not on AES. Build one static archive per ABI: `arm64-v8a`, `armeabi-v7a`,
   `x86_64`, Apple `arm64` (`-O3 -mcpu=native` / `-march=armv8-a+crypto`).

2. **Generate bindings** with `package:ffigen`, or hand-write `dart:ffi`
   `lookupFunction` calls. Load with `DynamicLibrary.open(...)` on Android and
   `DynamicLibrary.process()` on iOS (statically linked into the runner).

3. **Implement `PqLatticeProvider`.** Marshal once into native scratch
   (`malloc` + `asTypedList().setAll`), call, copy results back, `free`. Buffers
   are tiny (ML-KEM ct 1568 B, ML-DSA-87 sig 4627 B), so marshalling cost is
   noise. Sketch:

   ```dart
   final class PqCleanFfiProvider implements PqLatticeProvider {
     @override String get name => 'pqclean-ffi';

     @override
     (Uint8List, Uint8List) kemEncapsulate(
       PqKemAlgorithm algorithm, Uint8List publicKey, {Uint8List? nonce}) {
       final ct = calloc<Uint8>(algorithm.ciphertextBytes);
       final ss = calloc<Uint8>(algorithm.sharedSecretBytes);
       final pk = calloc<Uint8>(publicKey.length)
         ..asTypedList(publicKey.length).setAll(0, publicKey);
       try {
         _enc(algorithm)(ct, ss, pk);  // bound C function for this parameter set
         return (
           Uint8List.fromList(ct.asTypedList(algorithm.ciphertextBytes)),
           Uint8List.fromList(ss.asTypedList(algorithm.sharedSecretBytes)),
         );
       } finally {
         calloc..free(ct)..free(ss)..free(pk);
       }
     }
     // …kemGenerateKeyPair / kemDecapsulate / dsa* likewise…
   }
   ```

   > Note: PQClean's KEM `encapsulate` draws its own randomness, so it cannot
   > honour the deterministic `nonce` parameter the way `pqcrypto` does. If you
   > need the deterministic (KAT) path, bind the implementation's
   > `*_keypair_derand` / `*_enc_derand` entry points (or liboqs equivalents),
   > or skip the byte-identity KEM checks and rely on round-trip + signature
   > cross-verification in your provider test.

4. **Register at startup**, before any crypto:

   ```dart
   void main() {
     PqLattice.provider = PqCleanFfiProvider();
     // …
   }
   ```

5. **Gate it with the conformance harness** in your host package's test:

   ```dart
   import 'package:pqforge/pqforge.dart';
   // copy or depend on test/support/lattice_conformance.dart

   test('native provider conforms', () =>
       latticeProviderConformance(PqCleanFfiProvider()));
   test('native provider matches pure Dart (KAT)', () => assertProvidersAgree(
       const PqPureDartLatticeProvider(), PqCleanFfiProvider()));
   ```

   `assertProvidersAgree` enforces byte-identical seeded keygen + deterministic
   encapsulation and cross-verifiable signatures against the pure-Dart reference
   — the interop guarantee (a file sealed pure-Dart opens native, and vice
   versa). If the native KEM cannot run deterministically (point 3), drop to
   `latticeProviderConformance` (round-trip correctness) for the KEM and keep
   `assertProvidersAgree` for signatures.

## Acceptance (host-side)

- Per-op ML-KEM-1024 encaps / ML-DSA-87 sign ≥ 5× faster than pure Dart on
  arm64 (measured with the host's bench).
- `latticeProviderConformance(native)` passes; `assertProvidersAgree(pureDart,
  native)` passes (or the documented KEM exception applies).
