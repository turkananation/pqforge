# pqforge API reference

`pqforge` exposes its entire public API through a single import:

```dart
import 'package:pqforge/pqforge.dart';
```

That one entrypoint provides the whole stack:

| Layer | What you get |
| --- | --- |
| Core facade & primitives | `PqForge`, ML-KEM/ML-DSA, codecs, key custody, recipes — pure Dart over PointyCastle |
| Hybrid KEM combining | `PqForgeCombiner` (raw bytes) and the `SecretKey.deriveHybridSecretKey` extension |
| Built-in classical hybrid | `PqForgeHybridKeyAgreement` (X25519 + ML-KEM), `PqForgeHybridSigner` (ML-DSA + Ed25519) |
| AEAD wire packets | `PqForgeSecureSession` over AES-256-GCM / ChaCha20-Poly1305, pure-Dart or native backend |

`package:cryptography` is a standard dependency (it powers the hybrid, native-AEAD,
and `SecretKey` pieces). The pure-Dart classes use only PointyCastle internally, and
unused backends are tree-shaken from release builds — you pay only for the APIs you call.

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

Concat-only join (no HKDF). Use this for RFC 10024 TLS combiners; do **not**
call `combine()` for X25519MLKEM768 (that reverses the join and HKDF twice):

```dart
enum PqHybridConcatOrder { classicalThenPq, pqThenClassical }

PqForgeCombiner.concatenateSharedSecrets({
  required Uint8List classicalSharedSecret,
  required Uint8List postQuantumSharedSecret,
  PqHybridConcatOrder order = PqHybridConcatOrder.classicalThenPq,
});
```

### Option B — `SecretKey.deriveHybridSecretKey`

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

## 2. Built-in classical hybrid tier

The single `pqforge.dart` import includes batteries-included classical helpers
for CLI/server projects that do not want to supply their own classical stack.

### X25519 + ML-KEM key agreement

```dart
const PqForgeHybridKeyAgreement({
  PqForgeProfile profile = PqForgeProfile.balanced,
  PqClassicalKeyAgreementAlgorithm classicalAlgorithm =
      PqClassicalKeyAgreementAlgorithm.x25519,
});

Future<crypto.SimpleKeyPair> generateClassicalKeyPair({Uint8List? seed});

Future<PqHybridKeyAgreementResult> initiate({
  required crypto.SimplePublicKey serverClassicalPublicKey,
  required Uint8List serverKemPublicKey,
  required Uint8List deploymentSalt,    // 32 bytes
  Uint8List? transcriptContext,
  Uint8List? roleContext,
});

Future<Uint8List> accept({
  required crypto.SimpleKeyPair serverClassicalKeyPair,
  required Uint8List serverKemSecretKey,
  required PqHybridKeyAgreementRequest request,
  required Uint8List deploymentSalt,
  Uint8List? roleContext,
});
```

`PqHybridKeyAgreementRequest` carries the server public material, client X25519
public key, ML-KEM ciphertext, transcript context, and transcript hash. It has
`toJson()` / `fromJson()` for transport or server DTOs.

Byte-oriented X25519 and NIST-curve ECDH (the latter is **not** on the
`initiate`/`accept` X25519 handshake; it is for TLS hybrid groups):

```dart
static Future<Uint8List> x25519SharedSecret({
  required Uint8List secretKey,       // 32
  required Uint8List remotePublicKey, // 32
}); // 32-byte shared secret

static Future<Uint8List> p256SharedSecret({
  required Uint8List secretKey,       // 32-byte scalar
  required Uint8List remotePublicKey, // 65-byte uncompressed SEC1
}); // 32-byte x-coordinate

static Future<Uint8List> p384SharedSecret({
  required Uint8List secretKey,       // 48-byte scalar
  required Uint8List remotePublicKey, // 97-byte uncompressed SEC1
}); // 48-byte x-coordinate

static Future<({Uint8List publicKey, Uint8List secretKey})>
    generateP256KeyPairBytes({Uint8List? seed});
static Future<({Uint8List publicKey, Uint8List secretKey})>
    generateP384KeyPairBytes({Uint8List? seed});
```

`PqNistEcdh` is the synchronous PointyCastle implementation (uncompressed
SEC1, x-coordinate secret, full public-key validation).
`PqEcdsaP256` remains signatures only. Custom `PqClassicalProvider`
implementors must add the four `p256*` / `p384*` methods.

Sync KDF / AEAD / KEM-check helpers used by TLS/QUIC (caller-supplied
nonce; no session object):

```dart
PqBytes.sha384 / hmacSha384 / sha384OfStream
PqBytes.sha512 / hmacSha512 / sha512OfStream

PqSymmetricPrimitives.hkdfExtractSha256({required ikm, Uint8List? salt});
PqSymmetricPrimitives.hkdfExpandSha256({required prk, required info, required outputBytes});
PqSymmetricPrimitives.hkdfExtractSha384 / hkdfExpandSha384 / hkdfSha384

PqSymmetricPrimitives.supportsChaCha20Poly1305; // always true (Dart engine)

PqSymmetricPrimitives.chacha20Poly1305Encrypt({ // ciphertext || tag
  required key,   // 32
  required nonce, // 12, uniqueness is the caller's
  required plaintext,
  Uint8List? aad,
});
PqSymmetricPrimitives.chacha20Poly1305Decrypt(...); // throws PqForgeAuthTagException
// dart2js-safe. PointyCastle session ChaCha is not; do not copy its 2^53 check.

PqKemPrimitives.checkEncapsulationKey(PqKemAlgorithm kem, Uint8List ek);
```

Do **not** use `PqForgeSecureSession.encrypt` for TLS records: that path is
async, generates its own nonce, and prepends it.

### ML-DSA + Ed25519 / ECDSA-P256 dual signatures

`PqForgeHybridSigner` pairs an ML-DSA signature with a classical signature; pick
the classical algorithm via `classicalAlgorithm`:

| `PqClassicalSignatureAlgorithm` | Backend | Public key | Signature |
| --- | --- | --- | --- |
| `ed25519` | `package:cryptography` | 32 B | 64 B |
| `ecdsaP256` | PointyCastle (`PqEcdsaP256`, pure Dart) | 65 B uncompressed | 64 B (`r‖s`) |

```dart
const PqForgeHybridSigner({
  PqForgeProfile profile = PqForgeProfile.balanced,
  PqClassicalSignatureAlgorithm classicalAlgorithm =
      PqClassicalSignatureAlgorithm.ed25519, // or .ecdsaP256
});

// Classical keys are raw bytes (PqClassicalSignatureKeyPair) so both backends
// share one type. ed25519 accepts a 32-byte seed; ecdsaP256 is always random.
Future<PqClassicalSignatureKeyPair> generateClassicalKeyPair({Uint8List? seed});

Future<PqHybridSignature> sign({
  required Uint8List pqcSecretKey,
  required PqClassicalSignatureKeyPair classicalKeyPair,
  required Uint8List message,
  Uint8List? context,
  PqSignatureAlgorithm? pqcAlgorithm,
  PqDualSignaturePolicy policy = PqDualSignaturePolicy.requireBoth,
});

Future<bool> verify({
  required Uint8List pqcPublicKey,
  required Uint8List classicalPublicKey, // raw bytes
  required Uint8List message,
  required PqHybridSignature signature,
  Uint8List? context,
});
```

`PqHybridSignature` has `toJson()` / `fromJson()`. ECDSA-P256 uses RFC 6979
deterministic nonces and canonical low-S signatures; the standalone `PqEcdsaP256`
primitive (keygen / sign / verify over raw bytes) is also exported for use
without the hybrid wrapper.

---

## 3. AEAD secure sessions and wire packets

`PqForgeSecureSession` encrypts payloads into self-describing AEAD wire packets.
A configuration is a **cipher suite × engine provider**; all four combinations
produce the identical wire layout and are mutually interoperable.

| Cipher suite / Provider | `PqForgeEngineProvider.pureDart` | `PqForgeEngineProvider.nativeCryptography` |
| --- | --- | --- |
| `PqForgeCipherSuite.aes256Gcm` | PointyCastle `GCMBlockCipher` | cryptography `AesGcm` |
| `PqForgeCipherSuite.chaCha20Poly1305` | PointyCastle `ChaCha20Poly1305` | cryptography `Chacha20.poly1305Aead` |

### Wire format

```text
+-----------------------------+------------------------------------+
|      Nonce / IV (12 B)      |      Ciphertext + Tag (variable)   |
+-----------------------------+------------------------------------+
```

### `PqForgeSecureSession`

```dart
PqForgeSecureSession({
  required Uint8List secretKey,                 // 32 bytes
  required PqForgeCipherSuite cipherSuite,
  PqForgeEngineProvider engineProvider = PqForgeEngineProvider.pureDart,
});

Future<Uint8List> encrypt(Uint8List payload, {Uint8List? associatedData});
Future<Uint8List> decrypt(Uint8List packet,  {Uint8List? associatedData});
void dispose(); // zeroizes the session's key copy; further use throws StateError
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

PqForgePointyCastleAeadEngine(PqForgeCipherSuite suite);  // pure-Dart (PointyCastle)
PqForgeCryptographyAeadEngine(PqForgeCipherSuite suite);  // native (package:cryptography)
```

---

## 4. The `PqForge` facade

```dart
const PqForge({PqForgeProfile profile = PqForgeProfile.balanced});
```

| `PqForgeProfile` | KEM | Signature | SLH-DSA |
| --- | --- | --- | --- |
| `compact` | ML-KEM-512 | ML-DSA-44 | SLH-DSA-SHAKE-128f |
| `balanced` | ML-KEM-768 | ML-DSA-65 | SLH-DSA-SHAKE-192f |
| `maximum` | ML-KEM-1024 | ML-DSA-87 | SLH-DSA-SHAKE-256f |

Methods, grouped:

| Area | Methods |
| --- | --- |
| Key generation | `generateKeys` · `generateKemKeyPair` · `generateSignatureKeyPair` · `generateSignatureKeyPairFromSeed` · `generateSlhDsaKeyPair` · `exportSlhDsaPublicKey` / `exportSlhDsaSecretKey` |
| KEM | `encapsulate` · `decapsulate` |
| Signatures | `sign` / `verify` · `signSlhDsa` / `verifySlhDsa` · `signDocument` / `verifyDocument` · `signText` / `verifyText` · `signMedia` / `verifyMedia` · `signWebhook` / `verifyWebhook` · `signArtifact` / `verifyArtifact` · `issueToken` / `verifyToken` · `dualSign` / `dualVerify` |
| Encryption & envelopes | `encrypt` / `decrypt` · `sealToKemPublicKey` / `openFromKemSecretKey` · `sealAndSign` / `openSignedFromKemSecretKey` · `encryptFileBytes` / `decryptFileBytes` · `encryptRecord` · `sealEmail` / `openEmail` · `sealText` / `openText` · `sealMedia` / `openMedia` · `encryptFolderEntry` / `decryptFolderEntry` |
| Key wrapping & identity | `wrapKeyWithPassphrase` / `unwrapKeyWithPassphrase` · `createIdentityBinding` / `verifyIdentityBinding` |
| Signed logs | `appendSignedLogEntry` / `verifySignedLogEntry` |
| Hybrid (legacy) | `deriveHybridSessionKey` (delegates to `PqForgeCombiner`) |
| Raw primitives | `hkdfSha256` · `hkdfExtractSha256` / `hkdfExpandSha256` · `hkdfSha384` · `hkdfExtractSha384` / `hkdfExpandSha384` · `aesGcmEncrypt` / `aesGcmDecrypt` · `chacha20Poly1305Encrypt` / `Decrypt` · `argon2id` · `checkEncapsulationKey` |

---

## 5. Supporting types

- **Algorithms & profiles:** `PqKemAlgorithm` (`mlKem512`, `mlKem768`, `mlKem1024`) · `PqSignatureAlgorithm` (`mlDsa44`, `mlDsa65`, `mlDsa87`) · `PqSlhDsaAlgorithm` (all 12 FIPS 205 sets) · `PqForgeProfile` (`compact`, `balanced`, `maximum`; each carries a matching SHAKE-f `slhDsa`) · `PqForgeException`. `SlhDsa` / `SlhDsaParams` / `SlhDsaPreHash` remain re-exported from `pqcrypto`.
- **Primitives:** `PqBytes` (`randomBytes`, `concat`, `sha256`, `sha384`, `sha512`, `hmacSha256`, `hmacSha384`, `hmacSha512`, `constantTimeEquals`, …) · `PqSymmetricPrimitives` · `PqKemPrimitives` · `PqSignaturePrimitives` · `PqSlhDsaPrimitives` · `PqNistEcdh` · `PqForgeBytes` (compatibility alias)
- **Keys & custody:** `PqKeyPair` · `PqKeyBundle` · `PqKemEncapsulation` · `PqExportedKey` · `PqWrappedKey` · `PqPassphraseKeyCustody` · `PqKeyCustodyStore` / `PqMemoryKeyCustodyStore` / `PqCallbackKeyCustodyStore` · `PqKeyStore` / `PqKeyResolver`
- **Codecs, recipes & DTOs:** `PqEnvelope` (`toBinary` / `fromBinary`, `toJson` / `fromJson`) · `PqIdentityBinding` · `PqSignedLogEntry` · `PqArtifactSignature` · `PqSignedToken` · `PqDualSignature` / `PqDualSignaturePolicy` · `PqHybridKeyAgreementRequest` / `PqHybridKeyAgreementResult` · `PqHybridSignature` · `PqRecipeMessages` · `PqOffloadRequest` / `PqOffloadResponse`

`package:pqforge/pqforge.dart` re-exports `package:pqcrypto/pqcrypto.dart`, so
`SlhDsa` / `SlhDsaParams` / `SlhDsaPreHash` are importable from the same barrel.
`PqForge.generateSlhDsaKeyPair` and CLI `keygen` emit SLH-DSA keys; detached
`sign`/`verify` (`document`, `text`, `media`, `artifact`) and recipe helpers
(`signDocument`, `signText`, `signMedia`, `signWebhook`, `signArtifact`) accept
them. Envelope headers, `.pqfs` signatures, `PqForgeHybridSigner`, signed
tokens, signed logs, and identity bindings stay ML-DSA-only. See
[HYBRID_AUDIT.md](HYBRID_AUDIT.md).

---

## CLI

```bash
export PQFORGE_PASSPHRASE='use-a-real-secret-manager-value'
dart run pqforge keygen --profile maximum --key-id vault --out-dir keys --passphrase-env PQFORGE_PASSPHRASE
dart run pqforge encrypt --recipient-public keys/vault.kem.public.json --in file.txt --out file.txt.pqf
dart run pqforge decrypt --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in file.txt.pqf --out file.open.txt
dart run pqforge encrypt-folder --recipient-public keys/vault.kem.public.json --in-dir ./docs --out-dir ./docs.pqf
dart run pqforge decrypt-folder --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in-dir ./docs.pqf --out-dir ./docs.open
dart run pqforge encrypt-text --recipient-public keys/vault.kem.public.json --text 'private memo' --text-id memo-1 --out memo.pqf
dart run pqforge decrypt-text --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in memo.pqf
dart run pqforge encrypt-media --recipient-public keys/vault.kem.public.json --in cover.png --mime-type image/png --out cover.png.pqf
dart run pqforge decrypt-media --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in cover.png.pqf --out cover.open.png
dart run pqforge sign --signer-secret keys/vault.sign.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --kind media --in cover.png --mime-type image/png --out cover.sig.json
dart run pqforge verify --signer-public keys/vault.sign.public.json --in cover.png --signature cover.sig.json
```

`keygen --out-dir` stores reusable key files in the selected directory. Public
keys are raw `PqExportedKey` JSON. With `--passphrase-env`, `--passphrase-file`,
or `--passphrase`, secret keys are written as Argon2id/AES-GCM `PqWrappedKey`
JSON (`*.wrapped.json`); without a passphrase, the CLI writes raw secret-key JSON
and emits a warning.

---

## Runnable examples

- [`example/pqforge_example.dart`](../example/pqforge_example.dart) — facade walkthrough
- [`example/file_encryption_example.dart`](../example/file_encryption_example.dart) — file envelopes + key custody
- [`example/hybrid_combiner_example.dart`](../example/hybrid_combiner_example.dart) — `PqForgeCombiner` (Options A & B)
- [`example/secure_session_example.dart`](../example/secure_session_example.dart) — `PqForgeSecureSession` across both backends
- [`example/hybrid_key_agreement_example.dart`](../example/hybrid_key_agreement_example.dart) — X25519 + ML-KEM, ML-DSA + Ed25519
- [`example/catalog_recipes_example.dart`](../example/catalog_recipes_example.dart) — webhook, sealed email, and signed token recipes
