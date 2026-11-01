---
title: HPKE
description: RFC 9180 seal, authenticated encapsulation, and export.
---

`PqHpke` implements [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180).
Four modes. Three KEMs this library can compute. Three KDFs. Three AEADs,
plus export-only.

| | |
| --- | --- |
| KEM | X25519, P-256, P-384 |
| KDF | HKDF-SHA256, HKDF-SHA384, HKDF-SHA512 |
| AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, export-only |
| Mode | base, PSK, auth, authPSK |

X448 and P-521 are not implemented. The KEM hash is fixed by the KEM id.
The suite KDF is only the key schedule, and the two may differ.

A sender context seals. A recipient context opens. `export` works on both
and does not move the sequence. A failed open does not move it either.

## Seal to a public key

Base mode. The recipient publishes a KEM public key. Associated data is
authenticated and is not encrypted.

```dart
final sealed = await PqHpke.seal(
  suite: HpkeSuite.x25519Aes128Gcm,
  mode: HpkeMode.base,
  recipientPublicKey: recipient.publicKey,
  info: Uint8List.fromList(utf8.encode('ledger v1')),
  aad: Uint8List.fromList(utf8.encode('desk=records')),
  plaintext: message,
);
```

`HpkeSuite.x25519Aes256Gcm` and `HpkeSuite.x25519ChaCha20Poly1305` are the
other X25519 one-liners. P-256 and P-384 take an explicit `HpkeSuite`.

## Say who encapsulated

Auth mode mixes the sender's KEM private key into the encapsulation. The
recipient must pass that sender's public key. A different sender does not
open. This is not an ML-DSA signature over the plaintext.

```dart
await PqHpke.seal(
  suite: HpkeSuite.x25519Aes128Gcm,
  mode: HpkeMode.auth,
  recipientPublicKey: recipient.publicKey,
  senderKey: sender,
  plaintext: message,
);
```

PSK and authPSK require a non-empty `psk` and `pskId`. Base and auth
reject a PSK. Setting only one of the two is an error in every mode.

## Export a secret

```dart
final setup = await PqHpke.setupSender(
  suite: const HpkeSuite(aead: HpkeAead.exportOnly),
  mode: HpkeMode.base,
  recipientPublicKey: recipient.publicKey,
  info: Uint8List.fromList(utf8.encode('channel v1')),
);
final secret = setup.context.export(
  Uint8List.fromList(utf8.encode('session')),
  32,
);
```

Export-only rejects `seal` and `open`. On the other AEADs you can seal and
export on the same context. Several seals are ordered: the sender's nth
seal is the recipient's nth open.

## What was checked

RFC 9180 known answers for X25519 and P-256, every mode, HKDF-SHA256 and
HKDF-SHA512, and every AEAD. One base vector is checked through sequence
256. P-384 is a round trip in every mode; that KEM is not in the vector
file the tests pin.

BoringSSL 0.20261020.0 `EVP_HPKE`, both directions: base and auth, X25519
and P-256, HKDF-SHA256 and HKDF-SHA384, AES-128-GCM, AES-256-GCM, and
ChaCha20-Poly1305, including a 32-byte export. `DeriveKeyPair` matches
`EVP_HPKE_KEY_derive` on those two KEMs.

That public API has no PSK setup, no P-384 KEM, and no HKDF-SHA512. Those
stay in the known-answer tests. OpenSSL is not the HPKE peer.

`setupSender`'s `ephemeralIkm` is the RFC ikm for every KEM. BoringSSL's
X25519 testing seed is the ephemeral private key instead. Leave the ikm
unset outside tests.

## The TLS shape

[pqtransport](https://github.com/turkananation/pqtransport) ECH uses base
mode, X25519, HKDF-SHA256, and AES-128-GCM. `info` is `tls ech`, a NUL,
and the original ECHConfig bytes. That stack still composes the steps
itself until it depends on this release. The calls are `setupSender` or
`setupRecipient`, then one `seal` or `open`.
