# Key Custody Architecture

V0.1 keeps key custody portable:

- `PqExportedKey` describes import/export bytes.
- `PqWrappedKey` encrypts key bytes with Argon2id + AES-GCM.
- `PqKeyCustodyStore` stores JSON documents in an app-selected backend.
- `PqPassphraseKeyCustody` wraps, stores, loads, and unwraps keys.
- `PqCallbackKeyCustodyStore` adapts databases, secure storage, Vault, KMS
  metadata tables, or Serverpod endpoints through callbacks.
- `PqMemoryKeyCustodyStore` is for tests and local demos only.

The core package does not depend on Flutter secure storage, cloud KMS, Vault, or
a filesystem keyring. Those belong in apps or optional adapter packages.

Treat seeds and secret-key bytes as equivalent to private keys. The package
provides containers and helpers; the application owns storage policy.

```dart
final backing = <String, Map<String, Object?>>{};
final store = PqCallbackKeyCustodyStore(
  putDocument: (id, json) => backing[id] = json,
  getDocument: (id) => backing[id],
  deleteDocument: backing.remove,
);

final forge = PqForge();
final custody = PqPassphraseKeyCustody(forge: forge, store: store);
final keys = forge.generateKeys(
  profile: PqForgeProfile.maximum,
  keyId: 'vault-key-2026-001',
);

await custody.wrapAndPut(
  keys.exportKemSecretKey(),
  userPassphrase,
);

final restored = await custody.getAndUnwrap(
  'vault-key-2026-001',
  userPassphrase,
);
```
