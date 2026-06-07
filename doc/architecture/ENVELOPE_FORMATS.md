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
8. AES-GCM payload
9. optional AAD hash
10. optional signer key ID
11. optional signature
12. JSON metadata

## JSON/base64 v1

JSON envelopes contain the same fields, with byte arrays encoded as base64.
Use this shape for APIs, Serverpod models, webhooks, and debug tooling.

## Compatibility

Envelope v1 must remain decodable after V1.0 unless a new magic/version pair is
introduced. New optional metadata can be added without changing the core frame.
