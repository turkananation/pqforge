# File Encryption

Use `encryptFileBytes` and `decryptFileBytes` for byte payloads that should be
stored or moved as encrypted files. The helper defaults to the maximum profile
because file archives often have long confidentiality lifetimes.

You supply file streaming/chunking, filenames, storage, backups, and key
custody. Do not load multi-GB files into memory in application code.

```dart
final forge = PqForge();
final recipient = forge.generateKeys(
  profile: PqForgeProfile.maximum,
  keyId: 'archive-key-a',
);
final custody = PqPassphraseKeyCustody(
  forge: forge,
  store: appKeyCustodyStore,
);

await custody.wrapAndPut(
  recipient.exportKemSecretKey(),
  userPassphrase,
);

final envelope = forge.encryptFileBytes(
  recipient.kemKeyPair.publicKey,
  fileBytes,
  aad: PqRecipeMessages.fileAad(fileName: fileName),
);

final restored = await custody.getAndUnwrap('archive-key-a', userPassphrase);
final opened = forge.decryptFileBytes(
  restored.bytes,
  envelope,
  aad: PqRecipeMessages.fileAad(fileName: fileName),
);
```

For local and server jobs, prefer wrapped CLI secret keys:

```bash
export PQFORGE_PASSPHRASE='use-a-real-secret-manager-value'
dart run pqforge keygen --key-id vault --out-dir keys --passphrase-env PQFORGE_PASSPHRASE
dart run pqforge encrypt-folder --recipient-public keys/vault.kem.public.json --in-dir ./records --out-dir ./records.pqf
dart run pqforge decrypt-folder --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in-dir ./records.pqf --out-dir ./records.open
```
