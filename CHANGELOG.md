## Unreleased — performance & memory

- Added a bounded-memory streaming envelope (`.pqfs`) for gigabyte-scale files: a
  signed master header followed by independently authenticated frames (per-frame
  `seq`/`isFinal` AAD binding prevents truncation, reordering, duplication, and
  splicing). Peak memory is a small, file-size-independent working set.
- Added the `package:pqforge/pqforge_io.dart` entrypoint with `PqForgeStreamCipher`
  (`encryptFile`/`decryptFile`/`readHeader`/`isStreamingFile`, engine selection
  via `forProvider`, and `Isolate.run` offload via `*InBackground`). The core
  `package:pqforge/pqforge.dart` library stays free of `dart:io` (web-safe).
- Envelope signatures are now computed over `SHA-256(header ‖ SHA-256(payload))`
  with `preHash:true`, so signing cost and memory no longer scale with payload
  size (previously the whole ciphertext was concatenated and signed).
- CLI `encrypt`/`decrypt`/`encrypt-media`/`decrypt-media` auto-route large inputs
  through streaming and auto-detect the format on read. `encrypt-folder`/
  `decrypt-folder` process files concurrently via a bounded per-file isolate pool
  (`--concurrency`).
- Removed redundant full-file `Uint8List.fromList(readAsBytes())` copies across
  the CLI ingestion paths.
- Added a synthetic, memory-tracked I/O benchmark (`test/benchmark_io_test.dart`,
  tag `benchmark`) with a 1.5× peak-RSS regression gate.
- Added independent `--kem` / `--sig` overrides so a strong KEM can pair with a
  lighter signature (the custom profile round-trips through both formats).
- Added a swappable lattice backend (`PqLatticeProvider`, `PqLattice.provider`)
  with the pure-Dart implementation as the default and a reusable
  conformance / KAT-equivalence test harness for validating native FFI backends.
- Added `pqforge pack` / `pqforge unpack`: pack a whole folder into one encrypted
  streaming archive (a single KEM encapsulation and signature for the entire
  tree), with path-traversal-safe restoration — ideal for many tiny files.
- Made the `package:cryptography` AEAD engine the default for all bulk streaming
  (measured ~11× the PointyCastle throughput even in pure Dart; hardware-backed
  on Flutter via `FlutterCryptography.enable()`); added `--engine
  cryptography|pure-dart` to every bulk CLI command. Wire formats are
  engine-independent.
- `pack`/`unpack` now stream end-to-end (`encryptStream`/`decryptStream`,
  `PqFolderPack.packStream`/`unpackFromStream`): no plaintext temp spool, no
  extra disk requirement, and a failed unpack removes everything it created.
- Hardened the streaming reader against hostile containers (header/signature
  length caps before allocation) and enforced the NIST SP 800-38D 2^32
  frames-per-key bound in nonce derivation.
- Added a FIPS deployment layer: `PqFipsMode` (AES-256-GCM-only suites,
  PBKDF2-only wrapping when enabled), PBKDF2-HMAC-SHA256 key wrapping
  (`wrapKeyWithPassphrase(kdf: PqKdf.pbkdf2HmacSha256)`, SP 800-132), and a
  swappable `PqRandom.generator` for validated-module DRBGs.
- Moved the `.pqfs` streaming codec into `package:pqforge/pqforge_io.dart` so
  the core `package:pqforge/pqforge.dart` stays dart2js-safe; exposed
  `PqBytes.decodeLengthPrefixed` and `PqForgeProfile.resolve`.
- CI now runs an enforced streaming peak-RSS regression gate (1.5× amplification
  budget at 64 MiB).

## 0.1.0

- Added algorithms, primitives, codecs,keys, recipes and service layers.
- Added binary and JSON envelope v1 formats.
- Added combined key bundles, portable key-store interfaces passphrase key wrapping, document signing, encrypted records/files, signed logs, identity bindings, artifact signing, dual-signature combiners, and isolate DTOs.
- Added the `/doc` documentation system, CI workflow, and expanded tests.
- Added typed ML-KEM and ML-DSA profiles for compact, balanced, and maximum parameter choices.
- Added ML-DSA detached signatures, ML-KEM KEM-DEM sealing/opening, signed encrypted envelopes, HKDF-SHA256 hybrid session derivation, AES-GCM helpers,transcript framing utilities, and strict byte-length checks.
- Added segmented examples and focused composition tests.
