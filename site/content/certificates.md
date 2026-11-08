---
title: Certificates
description: X.509 and PKCS#10 that openssl req can read, and the signatures they use.
---

`PqX509` parses a certificate, mints one, checks one signature, and checks
a path against anchors you pass in. `now` is an argument. There is no
socket, no system trust store, no AIA fetch, no OCSP fetch, and no CT.

A certificate `openssl req` can read is not a WebPKI CA.

The CLI matches `openssl req` and `openssl x509 -req`:

```bash
dart run pqforge cert req --subj '/CN=localhost' --keyout key.pem --out req.pem
dart run pqforge cert issue --ca ca.pem --ca-key ca-key.pem --in req.pem --out leaf.pem
dart run pqforge cert verify --ca ca.pem --in leaf.pem
```

`cert inspect` prints a certificate, a PKCS#10 request, or a private-key
PEM. It does not print the secret.

`cert sign` copies the request's extensions. `cert verify` reads PEM or DER.

## Signatures on that path

| API | What it is |
| --- | --- |
| `PqEcdsaP256` | ECDSA P-256, RFC 6979, low-S on sign. Verify accepts the high-S encoding other libraries put in a certificate. |
| `PqEcdsaP384` | ECDSA P-384 / SHA-384, raw `r \|\| s`, low-S. This is not `p384SharedSecret`. |
| `PqEd25519` | Synchronous RFC 8032. The field uses 16-bit limbs so it fits a dart2js integer. |
| `PqRsa` | PKCS#1 v1.5 and RSASSA-PSS, SHA-1/256/384/512. Verification accepts a 1024, 2048, 3072, or 4096 bit modulus. Generation stays 2048, 3072, or 4096. |
| ML-DSA | Through pqcrypto, the same as the rest of the package. |

CI checks a chain for each of those against pinned OpenSSL 4.1.0 and
BoringSSL 0.20261020.0. OpenSSL is the conformance oracle. BoringSSL is a
second verifier: it rejects a PSS salt other than the hash length and an
`id-RSASSA-PSS` SubjectPublicKeyInfo, so those two chains are OpenSSL only.

Name constraints cover DNS, IP, email, URI, and directory names. A name
form that cannot be evaluated fails closed. `id-pe-tlsfeature`
status_request is must-staple: the path fails until the caller says an
OCSP response was present. Explicit EC parameters are rejected.
