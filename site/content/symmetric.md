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

## Session packets

`PqForgeSecureSession` seals one payload into a self-describing packet.
The key is 32 bytes. The suite is `PqForgeCipherSuite.aes256Gcm` or
`chaCha20Poly1305`. The engine is `PqForgeEngineProvider.pureDart`
(PointyCastle) or `nativeCryptography` (`package:cryptography`). A packet
from one engine opens on the other. The wire layout is 12 nonce bytes,
then ciphertext, then the 16-byte tag.

```dart
final session = PqForgeSecureSession(
  secretKey: key,
  cipherSuite: PqForgeCipherSuite.aes256Gcm,
);
final packet = await session.encrypt(payload, associatedData: header);
final clear = await session.decrypt(packet, associatedData: header);
session.dispose();
```

`dispose` wipes the copy the session holds. It does not wipe copies you
kept. `PqFipsMode` refuses the ChaCha suite on this class. AES-128 is not
a session suite. It exists for HPKE and for QUIC Initial packets.

A failed tag throws `PqForgeAuthTagException`. The nonce is random per
packet. Do not reuse a key so long that a 96-bit random nonce is likely
to collide. This is not a record layer and it does not rotate keys.
Those calls are not a new envelope format.

## SHA-1

`PqBytes.sha1` and `sha1OfStream` are RFC 3174. The digest is 20 bytes.
`PqForgeBytes.sha1` is the same function.

Collision resistance is broken. The call exists because a few standards
still name SHA-1, including DNSSEC NSEC3 (RFC 5155) and DS digest type 1
(RFC 4034). It does not sign. A new protocol uses SHA-256, SHA-384, or
SHA-512. There is no HMAC-SHA1.
