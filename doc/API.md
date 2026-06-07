# pqforge API reference

`pqforge` exposes its public API through two import entrypoints.

| Import | What you get | Pulls in `package:cryptography`? |
| --- | --- | --- |
| `package:pqforge/pqforge.dart` | The full zero-dependency core: the `PqForge` facade, primitives, codecs, key custody, the hybrid `PqForgeCombiner`, the cipher-suite enums, and the pure-Dart AEAD engine. | No |
| `package:pqforge/pqforge_cryptography.dart` | Everything above (re-exported) **plus** the three `cryptography`-backed pieces: the `SecretKey` hybrid-combiner extension, the native AEAD engine, and `PqForgeSecureSession`. | Yes |

> Rule of thumb: import `pqforge.dart` unless you specifically want the `cryptography`-package ergonomics or the unified `PqForgeSecureSession`.

---

## 1. Hybrid KEM secret combining

Combine a classical shared secret with a post-quantum (ML-KEM) shared secret into
one symmetric key, using the IETF `classical || post-quantum` concatenate-then-HKDF
construction. Two profiles select the HKDF digest:

| `PqHybridProfile` | HKDF digest | Pairs with |
| --- | --- | --- |
| `balanced` | SHA-256 | ML-KEM-768 |
| `heavy` | SHA-512 | ML-KEM-1024 |

### Option A — `PqForgeCombiner` (core, raw bytes)

```dart
const PqForgeCombiner({PqHybridProfile profile = PqHybridProfile.balanced});
const PqForgeCombiner.balanced(); // SHA-256
const PqForgeCombiner.heavy();    // SHA-512

Uint8List combine({
  required Uint8List classicalSharedSecret,   // placed first (no length framing)
  required Uint8List postQuantumSharedSecret, // placed second
  required Uint8List info,                     // mandatory domain separation
  Uint8List? salt,                             // null/empty => RFC 5869 zero salt
  int length = PqForgeCombiner.defaultLength,  // 32
});

static void wipe(Uint8List buffer); // zeroization primitive
```

### Option B — `SecretKey.deriveHybridSecretKey` (cryptography entrypoint)

```dart
// extension PqForgeCryptographyExtensions on crypto.SecretKey
Future<crypto.SecretKeyData> deriveHybridSecretKey({
  required crypto.SecretKey postQuantumSecret,
  required Uint8List info,
  Uint8List? salt,
  PqHybridProfile profile = PqHybridProfile.balanced,
  int length = PqForgeCombiner.defaultLength,
});
```

Both paths yield byte-identical keys for identical entropy. The receiver is treated
as the classical secret; `postQuantumSecret` is placed second.

---

## 2. AEAD secure sessions and wire packets

`PqForgeSecureSession` encrypts payloads into self-describing AEAD wire packets.
A configuration is a **cipher suite × engine provider**; all four combinations
produce the identical wire layout and are mutually interoperable.

|  | `PqForgeEngineProvider.pureDart` | `PqForgeEngineProvider.nativeCryptography` |
| --- | --- | --- |
| `PqForgeCipherSuite.aes256Gcm` | PointyCastle `GCMBlockCipher` | cryptography `AesGcm` |
| `PqForgeCipherSuite.chaCha20Poly1305` | PointyCastle `ChaCha20Poly1305` | cryptography `Chacha20.poly1305Aead` |

### Wire format

```text
+-----------------------------+------------------------------------+
|      Nonce / IV (12 B)      |      Ciphertext + Tag (variable)   |
+-----------------------------+------------------------------------+
```

### `PqForgeSecureSession` (cryptography entrypoint)

```dart
PqForgeSecureSession({
  required Uint8List secretKey,                 // 32 bytes
  required PqForgeCipherSuite cipherSuite,
  PqForgeEngineProvider engineProvider = PqForgeEngineProvider.pureDart,
});

Future<Uint8List> encrypt(Uint8List payload, {Uint8List? associatedData});
Future<Uint8List> decrypt(Uint8List packet,  {Uint8List? associatedData});
```

- A fresh cryptographically secure 12-byte nonce is generated per `encrypt`.
- `associatedData` (AAD) is authenticated but not encrypted; the peer must supply
  the identical AAD to `decrypt`.
- Authentication failures (tampered nonce/ciphertext/tag or mismatched AAD) throw
  `PqForgeAuthTagException`; a structurally too-short packet throws `ArgumentError`.

### Lower-level AEAD engines

For seal/open without the session's nonce generation and wire framing:

```dart
abstract interface class PqForgeAeadEngine {
  PqForgeCipherSuite get cipherSuite;
  PqForgeEngineProvider get provider;
  Future<Uint8List> seal({required Uint8List key, required Uint8List nonce,
      required Uint8List plaintext, required Uint8List aad});       // -> ciphertext||tag
  Future<Uint8List> open({required Uint8List key, required Uint8List nonce,
      required Uint8List cipherTextWithTag, required Uint8List aad}); // throws PqForgeAuthTagException
}

PqForgePointyCastleAeadEngine(PqForgeCipherSuite suite);  // core (zero-dep)
PqForgeCryptographyAeadEngine(PqForgeCipherSuite suite);  // cryptography entrypoint
```

---

## 3. The `PqForge` facade

```dart
const PqForge({PqForgeProfile profile = PqForgeProfile.balanced});
```

| `PqForgeProfile` | KEM | Signature |
| --- | --- | --- |
| `compact` | ML-KEM-512 | ML-DSA-44 |
| `balanced` | ML-KEM-768 | ML-DSA-65 |
| `maximum` | ML-KEM-1024 | ML-DSA-87 |

Methods, grouped:

| Area | Methods |
| --- | --- |
| Key generation | `generateKeys` · `generateKemKeyPair` · `generateSignatureKeyPair` · `generateSignatureKeyPairFromSeed` |
| KEM | `encapsulate` · `decapsulate` |
| Signatures | `sign` / `verify` · `signDocument` / `verifyDocument` · `signArtifact` / `verifyArtifact` · `dualSign` / `dualVerify` |
| Encryption & envelopes | `encrypt` / `decrypt` · `sealToKemPublicKey` / `openFromKemSecretKey` · `sealAndSign` / `openSignedFromKemSecretKey` · `encryptFileBytes` / `decryptFileBytes` · `encryptRecord` |
| Key wrapping & identity | `wrapKeyWithPassphrase` / `unwrapKeyWithPassphrase` · `createIdentityBinding` / `verifyIdentityBinding` |
| Signed logs | `appendSignedLogEntry` / `verifySignedLogEntry` |
| Hybrid (legacy) | `deriveHybridSessionKey` (delegates to `PqForgeCombiner`) |
| Raw primitives | `hkdfSha256` · `aesGcmEncrypt` / `aesGcmDecrypt` · `argon2id` |

---

## 4. Supporting types

- **Algorithms & profiles:** `PqKemAlgorithm` (`mlKem512`, `mlKem768`, `mlKem1024`) · `PqSignatureAlgorithm` (`mlDsa44`, `mlDsa65`, `mlDsa87`) · `PqForgeProfile` (`compact`, `balanced`, `maximum`) · `PqForgeException`
- **Primitives:** `PqBytes` (`randomBytes`, `concat`, `sha256`, `hmacSha256`, `constantTimeEquals`, …) · `PqSymmetricPrimitives` · `PqKemPrimitives` · `PqSignaturePrimitives` · `PqForgeBytes` (compatibility alias)
- **Keys & custody:** `PqKeyPair` · `PqKeyBundle` · `PqKemEncapsulation` · `PqExportedKey` · `PqWrappedKey` · `PqPassphraseKeyCustody` · `PqKeyCustodyStore` / `PqMemoryKeyCustodyStore` / `PqCallbackKeyCustodyStore` · `PqKeyStore` / `PqKeyResolver`
- **Codecs, recipes & DTOs:** `PqEnvelope` (`toBinary` / `fromBinary`, `toJson` / `fromJson`) · `PqIdentityBinding` · `PqSignedLogEntry` · `PqArtifactSignature` · `PqDualSignature` / `PqDualSignaturePolicy` · `PqRecipeMessages` · `PqOffloadRequest` / `PqOffloadResponse`

---

## Runnable examples

- [`example/pqforge_example.dart`](../example/pqforge_example.dart) — facade walkthrough
- [`example/file_encryption_example.dart`](../example/file_encryption_example.dart) — file envelopes + key custody
- [`example/hybrid_combiner_example.dart`](../example/hybrid_combiner_example.dart) — `PqForgeCombiner` (Options A & B)
- [`example/secure_session_example.dart`](../example/secure_session_example.dart) — `PqForgeSecureSession` across both backends
