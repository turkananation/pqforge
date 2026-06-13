# Performance

`pqforge` is pure Dart, so the **AEAD engine — not the lattice — is the
bulk-throughput lever**. Profile choice (compact/balanced/maximum) changes
per-file constants and sizes, not MiB/s.

> Numbers below are measured on an Intel i5-1135G7 (4 physical cores / 8
> threads), Dart 3.12.0, linux_x64. The full as-built audit, with methodology
> and projections, is in
> [PERFORMANCE_AUDIT_AND_HYBRID_CLI.md](https://github.com/turkananation/pqforge/blob/main/doc/technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md).

## Engine: default to `cryptography`

`--engine cryptography` (the default) is roughly **10× the PointyCastle
throughput** even in pure Dart, and hardware-backed on Flutter via
`FlutterCryptography.enable()`. `--engine pure-dart` is the PointyCastle
reference. Wire formats are engine-independent, so a file sealed by one engine
opens on the other.

## Cipher: ChaCha20-Poly1305 for pure-Dart bulk

Where hardware AES is **not** dispatched (most pure-Dart hosts and background
isolates):

| Cipher | Pure-Dart throughput |
| --- | --- |
| ChaCha20-Poly1305 | **30.4 MiB/s** |
| AES-256-GCM | 11.5 MiB/s |

That is a **2.6×** bulk win — `--cipher chacha20-poly1305`. With hardware AEAD
(the OpenSSL ceiling, measured as a dev tool) both exceed 1 GB/s
(AES-256-GCM ≈ 1122.8 MiB/s, ChaCha20-Poly1305 ≈ 1049.2 MiB/s), which is the
documented cost of staying pure Dart and web-first.

## Picking the path

| Workload | Use | Why |
| --- | --- | --- |
| File < 8 MiB | `encrypt` (one-shot, auto) | runs the DEM on the fast engine; ~3× payload RAM |
| File ≥ 8 MiB | `encrypt` (auto `.pqfs`) | bounded memory; ~2-frame working set |
| Many large files | `encrypt-folder --concurrency <physical cores>` | per-file isolates; ~3.3× on 4 cores |
| Many tiny files | `pack` | one KEM + one signature for the whole tree; ~100× less ciphertext overhead than per-file envelopes for 1000 small files |
| GB-scale signing | `hybrid-sign --digest` / `ecdsa-sign --digest` | streamed SHA-256, O(1) memory |

## Keys

`keygen` wraps secret keys on a bounded isolate pool (`--wrap-concurrency`,
default 2). A full default keygen-with-passphrase (ML-KEM + ML-DSA + X25519 +
Ed25519 + ECDSA-P256, all wrapped) is ≈ 2.9 s wall on the reference host.

## Memory safety net

CI enforces a streaming peak-RSS regression gate (1.5× payload amplification at
64 MiB), so the bounded-memory guarantee cannot silently regress.

## See also

- [Streaming And Large Files](Streaming-And-Large-Files)
- [Multi-Recipient And Hybrid](Multi-Recipient-And-Hybrid)
- [CLI Guide](CLI-Guide)
