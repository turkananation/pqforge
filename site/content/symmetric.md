---
title: Symmetric
description: AES-GCM, ChaCha20-Poly1305, and the ChaCha20 keystream.
---

Two AEADs sit under the envelopes and under HPKE.

| Call | Key | Nonce | Returns |
| --- | --- | --- | --- |
| `PqSymmetricPrimitives.aesGcmEncrypt` | 32 | 12 | ciphertext then a 16-byte tag |
| `PqSymmetricPrimitives.aes128GcmEncrypt` | 16 | 12 | ciphertext then a 16-byte tag |
| `PqSymmetricPrimitives.chacha20Poly1305Encrypt` | 32 | 12 | ciphertext then a 16-byte tag |

AES-128 exists because HPKE and QUIC Initial packets need it. The session
helper `PqForgeSecureSession` is still AES-256-GCM or ChaCha20-Poly1305.
The ChaCha AEAD uses the Dart engine in `package:cryptography`, so it runs
on dart2js. Web Crypto has no ChaCha.

A failed tag throws `PqForgeAuthTagException`. RC4 is not implemented.

## ChaCha20 keystream

`PqSymmetricPrimitives.chacha20` is RFC 8439, not an AEAD.

- 32-byte key
- 12-byte nonce
- caller-supplied 32-bit block counter
- 1 to 4096 keystream bytes

QUIC header protection (RFC 9001 §5.4.4) takes the first 5 bytes. The
sample's little-endian counter is the counter, and the sample's last 12
bytes are the nonce. Initial packets do not use this function. They use
`aesEncryptBlock`.

The AEAD is a different function. It forces the counter to 1 and appends a
Poly1305 tag. Do not use the AEAD as the mask, and do not use the keystream
as the AEAD.

HKDF-Extract and HKDF-Expand are exported for SHA-256 and SHA-384.
HPKE's SHA-512 schedule uses the same HMAC-SHA512 the package already had.
Those calls are not a new envelope format.
