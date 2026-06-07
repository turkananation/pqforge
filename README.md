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
