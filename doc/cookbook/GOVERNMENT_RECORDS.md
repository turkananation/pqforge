# Government Records

Use `encryptRecord` for confidential records and `appendSignedLogEntry` for
tamper-evident audit trails. Prefer the maximum profile for long-lived archives.
`encryptRecord` is ML-KEM. The log signature may be ML-DSA (the default) or
SLH-DSA via `slhDsa:`. Each entry binds the previous entry hash, the payload,
and the timestamp. `entryHash` is SHA-256 of that message plus the signature,
so the next call can chain it. An envelope signature on the ciphertext, if you
add one, stays ML-DSA.

```dart
const slhAlg = PqSlhDsaAlgorithm.shake256f;
final slh = forge.generateSlhDsaKeyPair(algorithm: slhAlg);
final entry = forge.appendSignedLogEntry(
  signerSecretKey: slh.secretKey,
  previousHash: Uint8List(32),
  payload: recordBytes,
  timestampMs: timestampMs,
  slhDsa: slhAlg,
);
final ok = forge.verifySignedLogEntry(slh.publicKey, entry);
final next = entry.entryHash();
```

Use maximum's `shake256f` only when the confidentiality lifetime of the archive
is why you picked that profile. A compact `shake128f` key is the faster default.

You supply classification policy, custodian workflows, key rotation, access
control, and independent audit requirements.
