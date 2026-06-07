# pqforge

`pqforge` is a Dart composition package for application-grade post-quantum
workflows. It combines `pqcrypto` ML-KEM/ML-DSA primitives with Pointy Castle
HKDF, AES-GCM, SHA-256, HMAC, and Argon2id helpers behind easy APIs.

The core workflow is intentionally simple:

```dart
final forge = PqForge();
final keys = forge.generateKeys();

final signature = forge.signDocument(
  keys.signatureKeyPair.secretKey,
  documentBytes,
  documentId: 'contract-2026-001',
);

final envelope = forge.encryptFileBytes(
  keys.kemKeyPair.publicKey,
  fileBytes,
);

final opened = forge.decryptFileBytes(
  keys.kemKeyPair.secretKey,
  envelope,
);
```

## What pqforge gives you

| Need | API |
| --- | --- |
| Generate encryption and signing keys | `generateKeys()` |
| Detached byte signatures | `sign()` / `verify()` |
| Document signing | `signDocument()` / `verifyDocument()` |
| Encrypt/decrypt payloads | `encrypt()` / `decrypt()` |
| Encrypt/decrypt files | `encryptFileBytes()` / `decryptFileBytes()` |
| Binary file envelopes | `PqEnvelope.toBinary()` / `PqEnvelope.fromBinary()` |
| JSON API envelopes | `PqEnvelope.toJson()` / `PqEnvelope.fromJson()` |
| Passphrase key wrapping | `wrapKeyWithPassphrase()` / `unwrapKeyWithPassphrase()` |
| Pluggable wrapped-key custody | `PqPassphraseKeyCustody` + `PqKeyCustodyStore` |
| Identity key bindings | `createIdentityBinding()` / `verifyIdentityBinding()` |
| Signed logs and artifacts | `appendSignedLogEntry()` / `signArtifact()` |
| Hybrid session derivation | `deriveHybridSessionKey()` |
| Hybrid KEM secret combining | `PqForgeCombiner` / `SecretKey.deriveHybridSecretKey()` |
| AEAD secure sessions & wire packets | `PqForgeSecureSession` |

## Hybrid KEM secret combining

When you run a classical KEX (such as X25519) alongside ML-KEM, the two shared
secrets must be combined safely. `PqForgeCombiner` implements the
concatenate-then-KDF construction from the IETF hybrid drafts
(`draft-ietf-tls-hybrid-design`, `draft-kwiatkowski-tls-ecdhe-mlkem`): the
classical secret is placed first, the post-quantum secret second (no length
framing, since each length is fixed by the ciphersuite), and the join is run
through HKDF.

There are two entry strategies:

```dart
// Option A — zero-dependency core, raw bytes (package:pqforge/pqforge.dart):
final sessionKey = const PqForgeCombiner.balanced().combine(
  classicalSharedSecret: x25519Shared, // fixed length per ciphersuite
  postQuantumSharedSecret: mlKemShared, // 32 bytes for ML-KEM
  info: Uint8List.fromList(utf8.encode('myapp/session/v1/client')), // required
);

// Option B — package:cryptography SecretKey extension
// (package:pqforge/pqforge_cryptography.dart):
final session = await classicalSecret.deriveHybridSecretKey(
  postQuantumSecret: mlKemSecret,
  info: Uint8List.fromList(utf8.encode('myapp/session/v1/client')),
  profile: PqHybridProfile.heavy,
);
```

| Profile | HKDF digest | Pairs with |
| --- | --- | --- |
| `PqHybridProfile.balanced` | SHA-256 | ML-KEM-768 |
| `PqHybridProfile.heavy` | SHA-512 | ML-KEM-1024 |

The `info` label is mandatory: it provides domain separation so a key derived
for one protocol context can never collide with another. The core
(`package:pqforge/pqforge.dart`) depends only on Pointy Castle; the `SecretKey`
extension lives in `package:pqforge/pqforge_cryptography.dart` so apps that do
not use `package:cryptography` never pull it in.

## Secure sessions and wire packets

Once you hold a 32-byte session key (for example from `PqForgeCombiner` above),
`PqForgeSecureSession` encrypts application payloads into self-describing AEAD
wire packets. Pick a cipher suite and a backend engine explicitly:

```dart
import 'package:pqforge/pqforge_cryptography.dart';

final session = PqForgeSecureSession(
  secretKey: derivedHybridKey,                     // 32 bytes
  cipherSuite: PqForgeCipherSuite.chaCha20Poly1305,
  engineProvider: PqForgeEngineProvider.pureDart,  // or .nativeCryptography
);

final packet = await session.encrypt(payload, associatedData: header);
final clear = await session.decrypt(packet, associatedData: header);
```

Every packet is one contiguous byte array — a fresh random 12-byte nonce
followed by the ciphertext and its 16-byte authentication tag:

```text
+-----------------------------+------------------------------------+
|      Nonce / IV (12 B)      |      Ciphertext + Tag (variable)   |
+-----------------------------+------------------------------------+
```

| Cipher suite | Best for |
| --- | --- |
| `PqForgeCipherSuite.aes256Gcm` | Hardware with AES-NI acceleration |
| `PqForgeCipherSuite.chaCha20Poly1305` | Software-only platforms / mobile CPUs |

| Engine provider | Backend |
| --- | --- |
| `PqForgeEngineProvider.pureDart` | PointyCastle (zero native dependencies) |
| `PqForgeEngineProvider.nativeCryptography` | `package:cryptography` (may use OS acceleration) |

Both backends emit the identical `nonce || ciphertext || tag` layout, so a
packet sealed by one decrypts cleanly under the other. A fresh nonce is
generated for every `encrypt`; `associatedData` (AAD) is authenticated but not
encrypted; and any authentication failure — tampered nonce, ciphertext, tag, or
mismatched AAD — throws `PqForgeAuthTagException`.

## Profiles

```dart
const compact = PqForge(profile: PqForgeProfile.compact);
const balanced = PqForge(); // ML-KEM-768 + ML-DSA-65
const maximum = PqForge(profile: PqForgeProfile.maximum);
```

| Profile | KEM | Signature | Use |
| --- | --- | --- | --- |
| `compact` | ML-KEM-512 | ML-DSA-44 | Smaller demos and constrained use |
| `balanced` | ML-KEM-768 | ML-DSA-65 | Default category-3 application profile |
| `maximum` | ML-KEM-1024 | ML-DSA-87 | Long-lived files, records, and archives |

File and record helpers default to the maximum profile because stored data often
has a long confidentiality lifetime.

## Pluggable key custody

`pqforge` wraps keys, but your app decides where wrapped-key JSON is stored.
Use the callback adapter for databases, secure storage, KMS metadata stores, or
Serverpod endpoints:

```dart
final store = PqCallbackKeyCustodyStore(
  putDocument: (id, json) => database.saveKey(id, json),
  getDocument: (id) => database.loadKey(id),
  deleteDocument: (id) => database.deleteKey(id),
);

final forge = PqForge();
final custody = PqPassphraseKeyCustody(forge: forge, store: store);
final keys = forge.generateKeys(
  profile: PqForgeProfile.maximum,
  keyId: 'file-key-2026-001',
);

await custody.wrapAndPut(keys.exportKemSecretKey(), userPassphrase);

final restored = await custody.getAndUnwrap(
  'file-key-2026-001',
  userPassphrase,
);
```

## Package boundary

`pqforge` owns composition: envelopes, KEM-DEM encryption, signatures, recipe
messages, key wrapping, and strict length checks.

Your app still owns public-key trust, user identity vetting, classical KEX,
transport security, replay stores, sessions, platform secure storage, KMS/HSM,
and legal/compliance policy.

## Documentation

- [API reference](doc/API.md)
- [Technical blueprint](doc/technical/PQFORGE_TECHNICAL_BLUEPRINT.md)
- [Roadmap](doc/roadmap/ROADMAP.md)
- [Project tracker](doc/roadmap/PROJECT_TRACKER.md)
- [Envelope formats](doc/architecture/ENVELOPE_FORMATS.md)
- [Key custody](doc/architecture/KEY_CUSTODY.md)
- [Cookbook](doc/cookbook/README.md)
- [Claim boundary](doc/security/CLAIM_BOUNDARY.md)
- [CI plan](doc/ci/CI_PLAN.md)

## Claim boundary

Allowed: "FIPS 203-aligned ML-KEM through `pqcrypto`",
"FIPS 204-aligned ML-DSA through `pqcrypto`", and "best-effort cleanup in Dart".

Do not claim: "FIPS validated", "CMVP validated", "certified",
"constant-time Dart guarantee", "secure memory erasure guarantee", or "ML-KEM
alone is secure transport".

## Validation

```bash
dart format --output=none --set-exit-if-changed .
dart analyze
dart test
dart run example/pqforge_example.dart
dart pub publish --dry-run
```
