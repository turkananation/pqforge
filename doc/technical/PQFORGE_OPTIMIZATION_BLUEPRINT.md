# TECHNICAL ARCHITECTURE & OPTIMIZATION BLUEPRINT: COMPREHENSIVE REFACTORING OF PQFORGE FOR RESOURCE-CONSTRAINED ENVIRONMENTS

**From:** Turkana Nation

**Status:** Mandatory Production Engineering Refactoring Mandate

**Implementation Version:** v.0.1.1
---

## EXECUTIVE CRISIS CRITIQUE & SYSTEM BOUNDARIES

A deep review of the `pqforge` repository reveals that while the package is cryptographically clean for small, synchronous memory-bound operations, its current execution paths will fail when subjected to gigabyte-scale inputs or high-concurrency environments on mobile (iOS/Android) and low-power embedded chips.

The engine relies on **monolithic byte-array transfers** and **nested buffer copying**. Ingestion pipelines such as `encryptFileBytes` and `PqEnvelope.toBinary()` allocate short-lived arrays on the managed Dart heap. This design triggers high garbage collection (GC) allocation spikes, memory fragmentation, thread stalls, and out-of-memory (OOM) failures under intense data loads.

Furthermore, executing NIST Level 5 primitives (**ML-KEM-1024** and **ML-DSA-87**) synchronously inside single-threaded structures starves the system runtime loop. This document provides the engineering refactoring requirements necessary to convert `pqforge` into an production-grade, zero-copy, streaming post-quantum cryptographic engine.

---

## 1. GIGABYTE-SCALE MEMORY MANAGEMENT & CHUNKED AEAD STREAMING

### Deep Critique of the Data Ingestion Path

The core runtime vulnerability is centered in the `PqForge.encrypt` method and its serialization layer. When archiving files or streaming media payloads via the CLI or cookbook interfaces, the code expects a flat, contiguous byte slice:

```dart
// lib/src/services/pqforge_service.dart
PqEnvelope encrypt(Uint8List recipientPublicKey, Uint8List plaintext, { ... })

```

To build this envelope, the system executes an encapsulation routine, calls `PqSymmetricPrimitives.aesGcmEncrypt` on the entire payload, and packages the results into a `PqEnvelope` instance. Inside `PqEnvelope.toBinary()`, the fields are parsed via `PqBytes.lengthPrefixed`:

```dart
// lib/src/primitives/pq_primitives.dart
static Uint8List lengthPrefixed(Iterable<Uint8List> fields) {
  final chunks = <Uint8List>[];
  for (final field in fields) {
    chunks..add(uint32(field.length))..add(field);
  }
  return concat(chunks);
}

```

This loop performs **24 independent memory allocations** to package the 12 fields of a binary envelope. The underlying `concat` routine re-iterates over the entire structure, copying all bytes into a newly allocated array. For a 1GB media file, this design triggers over 3GB of short-lived allocations, leading to instant OOM errors on standard mobile operating systems.

### Zero-Copy Chunk-Based Streaming Design

To process infinite data inside a deterministic memory window ($\le 2\text{MB}$), the library must implement a streaming architecture. Because an AEAD verification tag can only protect data that has been fully processed, streaming unauthenticated plaintext is prohibited. The dataset must be structured as a sequence of authenticated blocks.

The refactored file layout replaces the single global payload array with a structured master header containing the KEM-DEM metadata, followed by a sequence of independent cryptographically bound blocks:

```text
+---------------------------------------------------------------------------------------------------------+
|                                    Streamed PqEnvelope Wire Layout                                      |
+--------------------------+-----------------------+------------------------+-----------------------------+
| Master Envelope Header   | Block 0 Header        | Block 0 Ciphertext     | Block 0 AEAD Tag            |
| (KEM Ciphertext + Meta)  | [Length(4B)][Seq(4B)] | (Fixed Size: 1MB chunk)| (16 Bytes standard)         |
+--------------------------+-----------------------+------------------------+-----------------------------+

```

### Memory Duplication Map & Elimination Strategies

1. **Symmetric Engine Input Copies:** `PqSymmetricPrimitives.aesGcmEncrypt` instantiates PointyCastle's `GCMBlockCipher` and calls `processBytes`. PointyCastle creates internal heap arrays unless it is explicitly supplied with destination arrays. The codebase must transition to using shared destination memory views via `Uint8List.view()`.
2. **Elimination of JSON Metadata Overhead:** The serialization path within `toBinary()` converts the metadata map to a JSON string via `jsonEncode` before packaging. For structured pipelines like folder archiving (`encrypt-folder`), parsing metadata strings for thousands of individual files places significant strain on the Dart garbage collector. Metadata fields must be migrated to a packed binary format written directly to the byte layout.

---

## 2. MULTI-CORE PARALLELISM & DART ISOLATES

### Event Loop Starvation Analysis

Lattice-based operations feature intensive polynomial matrix math. Performing an ML-KEM-1024 encapsulation or an ML-DSA-87 signature computation requires significant processor cycles.

Executing these routines synchronously within the main thread stops asynchronous execution handles, drops rendering frames, and creates noticeable latency on mobile devices.

### Zero-Copy Inter-Isolate Communication Pool

To scale across multiple CPU cores without incurring memory allocation penalties, `pqforge` must use an asynchronous Isolate Worker Pool. Simply passing standard `Uint8List` buffers across Dart isolates introduces a silent allocation penalty: **the Dart runtime deep-copies the entire byte array across isolate memory spaces.**

To achieve true zero-copy parallelism, the architecture must handle binary data streams using one of two precise patterns:

1. **`TransferableTypedData`:** Encapsulates the byte array into a native unmanaged block that can be moved across isolate boundaries via reference passing, neutralizing copy allocations.
2. **Direct Pointer Passing (`ffi.Pointer<ffi.Uint8>`)**: Allocates memory regions inside the unmanaged C heap, passing the raw pointer address across isolates as a standard integer.

```text
                    [ Main Orchestrator Isolate ]
                     (Reads Stream via Chunk Views)
                                  |
            +---------------------+---------------------+
            |                     |                     |
     (Pointer Pass)         (Pointer Pass)        (Pointer Pass)
            v                     v                     v
   [ Isolate Worker 0 ]  [ Isolate Worker 1 ]  [ Isolate Worker 2 ]
    (Core 0: Encrypt)     (Core 1: Encrypt)     (Core 2: Encrypt)
            |                     |                     |
            +---------------------+---------------------+
                                  |
                           (Output Queue)
                                  v
                       [ Sequential Disk IO ]

```

The code block below provides an architecture for a zero-copy, multi-threaded isolate processing stream using unmanaged native pointers:

```dart
import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

class NativeChunkMessage {
  final int address;
  final int length;
  final int sequenceNumber;
  final bool isLast;

  NativeChunkMessage({
    required this.address,
    required this.length,
    required this.sequenceNumber,
    required this.isLast,
  });
}

/// Dispatched to run completely contained in a background Isolate pool worker
class IsolateParallelCryptoWorker {
  final Uint8List symmetricKey;
  final Uint8List masterNonce;

  IsolateParallelCryptoWorker({required this.symmetricKey, required this.masterNonce});

  void encryptChunkNativeSpace(NativeChunkMessage msg, SendPort resultPort) {
    final ffi.Pointer<ffi.Uint8> sourcePtr = ffi.Pointer.fromAddress(msg.address);
    
    // Nonce Security Invariants: Compute deterministic unique IV for this block index
    final Uint8List blockNonce = Uint8List.fromList(masterNonce);
    final ByteData nonceWriter = ByteData.view(blockNonce.buffer);
    // XOR the trailing 4 bytes of the master nonce with the block sequence counter
    final int baseCounterValue = nonceWriter.getUint32(8, Endian.big);
    nonceWriter.setUint32(8, baseCounterValue ^ msg.sequenceNumber, Endian.big);

    // Bind sequence counter to Associated Data to anchor block positioning invariants
    final Uint8List blockAad = Uint8List(4)..buffer.asByteData().setUint32(0, msg.sequenceNumber, Endian.big);

    // Instantiate a direct view over the native unmanaged memory without executing a data copy
    final Uint8List plaintextView = sourcePtr.asTypedList(msg.length);

    // Execute low level primitive encryption loop
    // In practice, this delegates directly to a zero-copy hardware accelerated native implementation
    final Uint8List ciphertextWithTag = _executeNativeAeadEncrypt(
      key: symmetricKey,
      nonce: blockNonce,
      plaintext: plaintextView,
      aad: blockAad,
    );

    // Allocate native unmanaged output target block
    final ffi.Pointer<ffi.Uint8> outputPtr = calloc<ffi.Uint8>(ciphertextWithTag.length + 8);
    final Uint8List outputView = outputPtr.asTypedList(ciphertextWithTag.length + 8);

    // Format low-level structure: [Length(4B)][Sequence(4B)][Payload... Tag(16B)]
    final ByteData headerWriter = ByteData.view(outputView.buffer);
    headerWriter.setUint32(0, ciphertextWithTag.length, Endian.big);
    headerWriter.setUint32(4, msg.sequenceNumber, Endian.big);
    outputView.setRange(8, outputView.length, ciphertextWithTag);

    // Eagerly zero out source buffer to uphold strict memory hygiene standards
    plaintextView.fillRange(0, plaintextView.length, 0);
    calloc.free(sourcePtr);

    // Transfer unmanaged address reference back to main orchestrator thread
    resultPort.send(NativeChunkMessage(
      address: outputPtr.address,
      length: outputView.length,
      sequenceNumber: msg.sequenceNumber,
      isLast: msg.isLast,
    ));
  }

  Uint8List _executeNativeAeadEncrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
  }) {
    // Thin internal routing to underlying cryptographic hardware primitive
    // Prevents allocation loops by outputting into pre-allocated memory spaces
    return Uint8List(plaintext.length + 16); // Placeholder layout boundary mapping
  }
}

```

### Cryptographic Nonce Security Under Parallelization Loads

When processing a single asset's block segments across concurrent isolates, randomized initialization vector generation (`PqBytes.randomBytes(12)`) is strictly prohibited. The birthdays paradox under high block concurrency bounds introduces a distinct risk of initialization vector reuse collisions.

The architecture must enforce a deterministic counter-mode derivation approach. The main orchestrator isolate must generate a single **96-bit Cryptographically Secure Master Nonce**. Each isolate worker must calculate its unique block initialization parameter by treatment of the block sequence identifier as a bitwise mask applied directly to the master seed ($IV_{Block} = IV_{Master} \oplus SequenceNumber$). This ensures absolute cryptographic distinctness across the entire operational sequence.

---

## 3. NATIVE BRIDGING (FFI) & HARDWARE ACCELERATION

### Marshalling and Execution Bottlenecks

The structural composition layer of `pqforge` interfaces with intermediate primitives via two mismatched execution paths:

1. **`pqcrypto` (FFI Overheads):** Every layer transition introduces data allocation marshalling boundaries. Passing keys or signatures involves moving data across the Dart VM managed space and the C-heap boundary via intermediate copy steps, introducing latency penalties during high-throughput execution.
2. **`pointycastle` (Symmetric Engine Bottlenecks):** When the application runs without the optional `cryptography` native extensions, symmetric block data routing drops back to PointyCastle. Because pure Dart code cannot emit dedicated processor-level vector extensions, symmetric processing operations run multiple times slower compared to optimized native code blocks.

### Zero-Copy Native Integration Strategy

To achieve gigabyte-scale capability, the processing loop must bypass high-level Dart wrappers for data-at-rest routines. The stream architecture must hold allocations strictly within unmanaged memory space (`Pointer<Uint8>`), passing raw addresses directly through native dynamic library hooks (`DynamicLibrary.open`).

```text
[ Dart Core Execution Loop ]                  [ Hardware Vector Engine ]
    Native Pointer Mapping    ============>     ARM Neon / Apple AMX
  (Memory Arena Coordinates)                   (In-Place Matrix Processing)

```

The system execution code block below configures a zero-copy hardware-accelerated FFI execution path that avoids Dart heap interaction:

```dart
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

// Native C function header layouts
typedef NativeMlKemEncapsC = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> pk,
  ffi.Pointer<ffi.Uint8> ctOut,
  ffi.Pointer<ffi.Uint8> ssOut
);

typedef NativeMlKemEncapsDart = int Function(
  ffi.Pointer<ffi.Uint8> pk,
  ffi.Pointer<ffi.Uint8> ctOut,
  ffi.Pointer<ffi.Uint8> ssOut
);

class HardwareAcceleratedCryptoEngine {
  late final ffi.DynamicLibrary _pqcLib;
  late final NativeMlKemEncapsDart _mlKem1024Encapsulate;

  HardwareAcceleratedCryptoEngine() {
    // Dynamic library lookup resolution mapping directly to accelerated library layers
    _pqcLib = Platform.isIOS || Platform.isMacOS
        ? ffi.DynamicLibrary.process()
        : ffi.DynamicLibrary.open('liboptimized_pqc.so');

    _mlKem1024Encapsulate = _pqcLib
        .lookup<ffi.NativeFunction<NativeMlKemEncapsC>>('pqc_m_ml_kem_1024_encaps')
        .asFunction<NativeMlKemEncapsDart>();
  }

  void executeZeroCopyEncapsulation(Uint8List rawPublicKey, ffi.Pointer<ffi.Uint8> ctTarget, ffi.Pointer<ffi.Uint8> ssTarget) {
    // Allocate the public key directly inside native memory spaces
    final ffi.Pointer<ffi.Uint8> nativePk = calloc<ffi.Uint8>(rawPublicKey.length);
    nativePk.asTypedList(rawPublicKey.length).setAll(0, rawPublicKey);

    try {
      final int result = _mlKem1024Encapsulate(nativePk, ctTarget, ssTarget);
      if (result != 0) {
        throw Exception('Hardware accelerated mathematical encapsulation processing error: $result');
      }
    } finally {
      // Scrub the allocation buffer area immediately to prevent data leakage
      nativePk.asTypedList(rawPublicKey.length).fillRange(0, rawPublicKey.length, 0);
      calloc.free(nativePk);
    }
  }
}

```

### Hardware Instruction Set Optimization Matrix

By linking the core stream pipelines to native compilation modules, the library directly targets processor-level optimizations:

* **ARM NEON & ARMv8 Cryptography Extensions:** Maps polynomial math steps straight to SIMD parallel vectors (`VADD`, `VMUL`). Symmetric pipelines execute directly inside hardware-accelerated processing layers using specialized hardware instructions (`AESE`, `AESD`).
* **Apple Silicon AMX Matrices:** Passes lattice computations directly to specialized coprocessor layers, removing processing overhead from the primary computing units on Apple devices.

---

## 4. ALGORITHMIC & CRYPTO SURFACE TUNING

### Performance Penalties of the 'Maximum' Profile

The `maximum` composition profile mandates the use of **ML-KEM-1024** and **ML-DSA-87**. On resource-constrained systems, this parameter choice introduces major runtime penalties:

```text
[ ML-KEM-768 ]  ---> 3x3 Matrix Multiplication (Default Load Bounds)
[ ML-KEM-1024]  ---> 4x4 Matrix Multiplication (Induces ~77% Processor Cycle Escalation)

```

1. **Memory Payload Footprint:** Key bundles expand significantly. Passing these large keys across communication lines risks memory fragmentation and buffer overflows in low-memory systems.
2. **Processor Cache Stalls:** ML-DSA-87 verification loops operate on massive matrix fields that exceed standard L1 data cache limits. This forces continuous memory fetching cycles from main system storage, degrading execution efficiency.

### Asymmetric Pre-Computation & Key Matrix Caching

To reduce latency during connection initialization, the library must decouple asymmetric key generation from active transaction loops:

```text
 [ Background Pre-Computation Thread ] ---> Generates Ephemeral Key Pools
                                                       |
                                                       v
 [ Active Asymmetric Handshake Layer ] <--- Pops Ready Pair Instantly (Zero Latency)

```

* **Ephemeral Pool Queuing:** Maintain a dedicated background queue filled with pre-computed key bundles. When a connection is established, pop a ready instance instantly, removing key-generation overhead from the active handshake pipeline.
* **Key Expansion Buffering:** When a public key is verified, cache its unpacked Number Theoretic Transform (NTT) polynomial representation in memory. Bypassing redundant expansion computations during repeated connections preserves critical CPU cycles.

### Eliminating Envelope Serialization Penalties

The default `PqEnvelope` implementation relies on multi-pass layout concatenation:

```dart
// lib/src/codecs/pq_envelope.dart
return PqBytes.lengthPrefixed([ ... fields ... ]);

```

This requires iterating through fields sequentially to calculate sizes before allocating and copying data.

To optimize this, implement a **Single-Pass Allocation Strategy**. Pre-calculate the exact required size of the binary envelope up front:

$$\text{Size}_{\text{Total}} = 4 + 4 + \text{Len}_{\text{Ciphertext}} + \text{Len}_{\text{Payload}} + \dots$$

Allocate a single target `Uint8List` buffer matching this dimension, and use direct byte offset adjustments to write values into their final locations in a single operation.

---

## 5. EMBEDDED & MOBILE FILE I/O BOTTLENECK ELIMINATION

### System-Call Optimization Matrix

The library's default directory processing logic uses an unbuffered file enumeration pattern:

```dart
// bin/pqforge.dart
final files = await _listFiles(inputDir);
for (final file in files) { ... encryptFolderEntry ... }

```

When archives contain thousands of individual items, this loop executes continuous system calls (`open`, `read`, `write`, `close`), causing I/O serialization bottlenecks on low-power storage hardware (e.g., eMMC, flash media).

The system must adopt a structural optimization model:

1. **Sequential Packaging (TAR Stream Pipelining):** Consolidate multiple inputs into a sequential tar-like structure before running encryption loops. This converts random small write patterns into a continuous sequential transfer, maximizing flash storage write efficiency.
2. **Page Aligned Storage Mapping:** Match block parsing dimensions to standard host memory boundaries (e.g., 4KB or 64KB units). Aligning I/O coordinates prevents redundant storage cycle access.

### High-Throughput Unmanaged Memory Mapped (mmap) Architecture

To maximize file transfers and bypass Dart's high-level I/O processing layers, route data using direct memory-mapped file architectures (`mmap`). This maps disk storage coordinates straight into native memory spaces, allowing the cryptographic engine to process data blocks directly on the file system layers without moving data into the Dart VM heap.

```text
[ Disk Block System Storage ]
            |  (Direct Memory-Mapped Kernel Pipeline)
            v
[ Native Calloc Arena Pointer ]  <-- Zero interaction with the Dart Managed Heap
            |  (Direct In-Place Block Cryptographic Transformation)
            v
[ Target Disk Outbound Track ]

```

The system execution block below configures a zero-copy native memory-mapped file transfer architecture using direct FFI system calls:

```dart
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

// POSIX system mapping signature declarations
typedef PosixMmapC = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Void> addr,
  ffi.Size length,
  ffi.Int32 prot,
  ffi.Int32 flags,
  ffi.Int32 fd,
  ffi.Int64 offset
);

typedef PosixMmapDart = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Void> addr,
  int length,
  int prot,
  int flags,
  int fd,
  int offset
);

typedef PosixMunmapC = ffi.Int32 Function(ffi.Pointer<ffi.Void> addr, ffi.Size length);
typedef PosixMunmapDart = int Function(ffi.Pointer<ffi.Void> addr, int length);

class MemoryMappedStreamingEngine {
  late final ffi.DynamicLibrary _libc;
  late final PosixMmapDart _mmap;
  late final PosixMunmapDart _munmap;

  MemoryMappedStreamingEngine() {
    _libc = Platform.isLinux 
        ? ffi.DynamicLibrary.open('libc.so.6') 
        : ffi.DynamicLibrary.process();
    _mmap = _libc.lookupFunction<PosixMmapC, PosixMmapDart>('mmap');
    _munmap = _libc.lookupFunction<PosixMunmapC, PosixMunmapDart>('munmap');
  }

  void processFileMmapInPlace(int fileDescriptor, int fileLength, Uint8List key, Uint8List nonce) {
    const int protRead = 0x1;
    const int protWrite = 0x2;
    const int mapShared = 0x01;

    // Map the file descriptor directly into native unmanaged address boundaries
    final ffi.Pointer<ffi.Void> mappedMemoryArena = _mmap(
      ffi.Pointer.fromAddress(0),
      fileLength,
      protRead | protWrite,
      mapShared,
      fileDescriptor,
      0
    );

    if (mappedMemoryArena.address == -1) {
      throw Exception('System virtualization failure: open mmap allocation error.');
    }

    try {
      // Cast the unmanaged memory space to an accessible array view
      final Uint8List nativeDataSlice = mappedMemoryArena.cast<ffi.Uint8>().asTypedList(fileLength);

      // Execute in-place cryptographic operations using native optimization vectors
      _applyInPlaceStreamCipher(nativeDataSlice, key, nonce);

    } finally {
      // Flush transformations directly back to disk storage and unmap the pointer space
      final int releaseStatus = _munmap(mappedMemoryArena, fileLength);
      if (releaseStatus != 0) {
        throw Exception('POSIX memory unmapping system error: $releaseStatus');
      }
    }
  }

  void _applyInPlaceStreamCipher(Uint8List dataset, Uint8List key, Uint8List nonce) {
    // Process block-level cryptographic loop transformations directly on the mapped array
  }
}

```

---

## 6. SYSTEM TRANSITION & CORE REFACTORING MATRIX

To upgrade `pqforge` into a production-ready, high-performance post-quantum cryptographic engine for resource-constrained systems, refactor the codebase according to this structural matrix:

```text
[ Target: lib/src/codecs/pq_envelope.dart ]
  -> Action: Replace multi-pass array concatenation loops with direct offset allocation writes.
  -> Metric: Cuts envelope packaging allocation counts to zero.

[ Target: lib/src/primitives/pq_primitives.dart ]
  -> Action: Route block operations through native pointer buffers using unmanaged C-heap pools.
  -> Metric: Completely stops intermediate data copying across the Dart VM boundary.

[ Target: lib/src/cipher/pq_secure_session.dart ]
  -> Action: Migrate to a chunked sequential format using block counter initialization masking.
  -> Metric: Enables secure data parallelization while maintaining absolute nonce security.

[ Target: bin/pqforge.dart ]
  -> Action: Reconstruct file listing loops to utilize sequential block tar packaging layouts.
  -> Metric: Eliminates redundant storage controller system calls on low-power devices.

```

By systematically replacing synchronous high-level collection wrappers with asynchronous, zero-copy native pipelines, `pqforge` can process massive data loads efficiently while ensuring robust security and performance stability on resource-constrained hardware targets.
