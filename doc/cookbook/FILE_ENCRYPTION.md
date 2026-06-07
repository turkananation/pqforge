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
  aad: PqBytes.utf8Bytes('file:$fileName'),
);

final restored = await custody.getAndUnwrap('archive-key-a', userPassphrase);
final opened = forge.decryptFileBytes(
  restored.bytes,
  envelope,
  aad: PqBytes.utf8Bytes('file:$fileName'),
);
```
