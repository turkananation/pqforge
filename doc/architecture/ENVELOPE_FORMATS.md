# Envelope Formats

## Binary v1

Binary envelopes use length-prefixed fields and are intended for files,
databases, queues, and durable storage.

Fields:

1. magic: `PQF1`
2. version
3. profile
4. ML-KEM algorithm ID
5. optional ML-DSA algorithm ID
6. nonce
7. KEM ciphertext
8. AEAD payload
9. optional AAD hash
10. optional signer key ID
11. optional signature
12. JSON metadata

## JSON/base64 v1

JSON envelopes contain the same fields, with byte arrays encoded as base64.
Use this shape for APIs, Serverpod models, webhooks, and debug tooling.

## Compatibility

Envelope v1 is still pre-1.0. The current CLI and recipes use structured AAD
labels such as `pqforge/file/v1`, `pqforge/folder-entry/v1`,
`pqforge/text-seal/v1`, and `pqforge/media-seal/v1`. New optional metadata can
be added without changing the core frame, but any future post-1.0 incompatible
change should use a new magic/version pair.
