# Text, Media, And Folders

Use `sealText` / `openText` for UTF-8 strings, `sealMedia` / `openMedia` for
images, audio, video, and PDFs, and `encryptFolderEntry` /
`decryptFolderEntry` for preserving a folder tree one encrypted envelope per
file.

`signText` and `signMedia` bind recipe-specific identifiers, MIME type where
applicable, payload hash, and payload length. Those detached signatures accept
ML-DSA or SLH-DSA (`slhDsa:`). `encryptFolderEntry` binds the relative path into
AAD, so moving an encrypted folder entry to another path does not silently
authenticate as the same file.

A signature inside an envelope (`signerSecretKey` on `sealText`, `sealMedia`,
or `encrypt`) is ML-DSA only. SLH-DSA belongs on `signText` / `signMedia` /
CLI `sign`, not on `--signer-secret`.

You supply MIME classification, folder inclusion/exclusion policy, large-file
streaming/chunking, storage layout, and key custody.

```dart
final forge = PqForge(profile: PqForgeProfile.maximum);
final recipient = forge.generateKeys(keyId: 'archive-key-a');
final signer = forge.generateSlhDsaKeyPair();

final textEnvelope = forge.sealText(
  recipient.kemKeyPair.publicKey,
  'private memo',
  textId: 'memo-2026-001',
  aad: PqBytes.utf8Bytes('tenant:demo'),
);
final text = forge.openText(
  recipient.kemKeyPair.secretKey,
  textEnvelope,
  aad: PqBytes.utf8Bytes('tenant:demo'),
);
final textSignature = forge.signText(
  signerSecretKey: signer.secretKey,
  text: text,
  textId: 'memo-2026-001',
  slhDsa: forge.profile.slhDsa,
);

final mediaEnvelope = forge.sealMedia(
  recipient.kemKeyPair.publicKey,
  mediaBytes,
  mediaId: 'cover.png',
  mimeType: 'image/png',
);
final mediaOk = forge.verifyMedia(
  signerPublicKey: signer.publicKey,
  mediaId: 'cover.png',
  mimeType: 'image/png',
  mediaBytes: mediaBytes,
  signature: forge.signMedia(
    signerSecretKey: signer.secretKey,
    mediaId: 'cover.png',
    mimeType: 'image/png',
    mediaBytes: mediaBytes,
    slhDsa: forge.profile.slhDsa,
  ),
  slhDsa: forge.profile.slhDsa,
);

final folderEntry = forge.encryptFolderEntry(
  recipient.kemKeyPair.publicKey,
  fileBytes,
  relativePath: 'contracts/lease.pdf',
);
```
