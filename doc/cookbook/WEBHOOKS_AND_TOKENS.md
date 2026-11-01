# Webhooks and Tokens

Use `signWebhook` / `verifyWebhook` to bind event type, timestamp, and payload
hash into a signed message. Use `issueToken` / `verifyToken` for signed API or
capability tokens with canonical JSON claims.

Both accept ML-DSA (the default) or SLH-DSA via `slhDsa:`. A token's JSON
`signatureAlgorithm` field is the id of whichever you passed. Version stays 1.
An older ML-DSA token still verifies: that path does not pre-hash. CLI
`sign --kind webhook` is the same webhook message (`--event-type`,
`--timestamp-ms`). The CLI does not enforce a replay window. Tokens and logs
stay library calls.

```dart
final slh = forge.generateSlhDsaKeyPair();
final signature = forge.signWebhook(
  signerSecretKey: slh.secretKey,
  eventType: 'invoice.paid',
  timestampMs: timestampMs,
  payload: payload,
  slhDsa: forge.profile.slhDsa,
);
final fresh = forge.verifyWebhook(
  signerPublicKey: slh.publicKey,
  eventType: 'invoice.paid',
  timestampMs: timestampMs,
  payload: payload,
  signature: signature,
  slhDsa: forge.profile.slhDsa,
  nowMs: timestampMs,
);

final token = forge.issueToken(
  signerSecretKey: slh.secretKey,
  issuer: 'issuer-a',
  subject: 'user-1',
  issuedAtMs: timestampMs,
  expiresAtMs: timestampMs + 60000,
  claims: {'role': 'reader'},
  slhDsa: forge.profile.slhDsa,
);
```

```bash
dart run pqforge sign \
  --signer-secret keys/archive.slh-dsa-shake-128f.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --kind webhook \
  --event-type invoice.paid \
  --timestamp-ms 1700000000000 \
  --in payload.json \
  --out payload.slh.sig.json
```

You supply timestamp windows, nonce/replay rejection, token schemas, revocation,
and key publication.
