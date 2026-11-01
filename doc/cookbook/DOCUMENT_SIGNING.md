# Document Signing

Use `signDocument` and `verifyDocument` for document-like payloads. The helper
signs a canonical message containing a domain label, document ID, document hash,
and document length. It does not sign the raw file bytes as the message.

The same helpers accept an optional `slhDsa:` parameter for FIPS 205 hash-based
signatures. `keygen` emits a profile-matched SHAKE-f SLH-DSA key next to the
ML-DSA bundle. Pass that secret to CLI `sign` / `verify` (`--kind document`,
`text`, `media`, `artifact`, or `webhook`), or pass `slhDsa:` in the library.
Do not pass `algorithm` and `slhDsa` together.

```dart
final forge = PqForge(profile: PqForgeProfile.compact);
final slh = forge.generateSlhDsaKeyPair();
final signature = forge.signDocument(
  slh.secretKey,
  documentBytes,
  documentId: 'contract-2026-001',
  slhDsa: forge.profile.slhDsa,
);
final ok = forge.verifyDocument(
  slh.publicKey,
  documentBytes,
  signature,
  documentId: 'contract-2026-001',
  slhDsa: forge.profile.slhDsa,
);
```

```bash
dart run pqforge sign \
  --signer-secret keys/archive.slh-dsa-shake-128f.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --kind document \
  --document-id contract-2026-001 \
  --in contract.pdf \
  --out contract.slh.sig.json
```

The same CLI kinds cover `text`, `media`, `artifact`, and `webhook`. Envelope
headers and `hybrid-sign` stay ML-DSA-only.

You supply document canonicalization, legal/e-signature policy, signer identity
vetting, and signature container UX.
