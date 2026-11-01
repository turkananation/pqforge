# HPKE

`PqHpke` is [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) Hybrid Public
Key Encryption. Import it from the web-safe entrypoint:

```dart
import 'package:pqforge/pqforge.dart';
```

It does not change `.pqf` or `.pqfs`. It is not TLS, not a trust store, and
not a FIPS module. X448 and P-521 are not implemented.

## Suites

| Piece | Values |
| --- | --- |
| KEM | DHKEM(X25519, HKDF-SHA256) `0x0020`, DHKEM(P-256, HKDF-SHA256) `0x0010`, DHKEM(P-384, HKDF-SHA384) `0x0011` |
| KDF | HKDF-SHA256 `0x0001`, HKDF-SHA384 `0x0002`, HKDF-SHA512 `0x0003` |
| AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, export-only `0xFFFF` |
| Mode | base `0x00`, PSK `0x01`, auth `0x02`, authPSK `0x03` |

The KEM's hash is fixed by the KEM id. The suite KDF is only the key
schedule. DHKEM(X25519, HKDF-SHA256) can be scheduled with HKDF-SHA512.

A sender context calls `seal`. A recipient context calls `open`. `export`
works on both and does not move the sequence number. A failed `open` does
not move it either. `dispose` scrubs the context secrets. That is
best-effort, not a claim that the bytes have left the process.

## Seal a message to a public key

Base mode. The recipient publishes a KEM public key. The sender encapsulates
to it and seals the plaintext. Associated data is authenticated and is not
encrypted.

```dart
final recipient = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
final sealed = await PqHpke.seal(
  suite: HpkeSuite.x25519Aes128Gcm,
  mode: HpkeMode.base,
  recipientPublicKey: recipient.publicKey,
  info: Uint8List.fromList(utf8.encode('app message v1')),
  aad: Uint8List.fromList(utf8.encode('recipient-id=7')),
  plaintext: Uint8List.fromList(utf8.encode('the record')),
);
final opened = await PqHpke.open(
  suite: HpkeSuite.x25519Aes128Gcm,
  mode: HpkeMode.base,
  enc: sealed.enc,
  ciphertext: sealed.ciphertext,
  recipientKey: recipient,
  info: Uint8List.fromList(utf8.encode('app message v1')),
  aad: Uint8List.fromList(utf8.encode('recipient-id=7')),
);
```

`info` is bound into the key schedule. The same `enc` opened with different
`info` fails closed. Send `enc` and `ciphertext`. Do not send the private key.

`HpkeSuite.x25519Aes256Gcm` and `HpkeSuite.x25519ChaCha20Poly1305` are the
other single-shot X25519 suites. P-256 and P-384 use `HpkeSuite(kem: ..., kdf: ..., aead: ...)`.

## Prove which sender encapsulated

Auth mode mixes the sender's KEM private key into the encapsulation. The
recipient passes that sender's public key to `open`. A ciphertext produced
by a different sender does not open. This is not a signature over the
plaintext and it is not ML-DSA.

```dart
final sealed = await PqHpke.seal(
  suite: HpkeSuite.x25519Aes128Gcm,
  mode: HpkeMode.auth,
  recipientPublicKey: recipient.publicKey,
  senderKey: sender,
  plaintext: plaintext,
);
await PqHpke.open(
  suite: HpkeSuite.x25519Aes128Gcm,
  mode: HpkeMode.auth,
  enc: sealed.enc,
  ciphertext: sealed.ciphertext,
  recipientKey: recipient,
  senderPublicKey: sender.publicKey,
);
```

PSK and authPSK take a non-empty `psk` and `pskId`. Base and auth reject a
PSK. PSK modes reject a missing one. One of the two set alone is an error
in every mode.

## Export a secret instead of sealing

`Context.Export` derives bytes from the exporter secret. The sequence number
is not an input, so an export taken before the first `seal` matches an
export taken after it, for the same context string and length.

```dart
final setup = await PqHpke.setupSender(
  suite: const HpkeSuite(aead: HpkeAead.exportOnly),
  mode: HpkeMode.base,
  recipientPublicKey: recipient.publicKey,
  info: Uint8List.fromList(utf8.encode('channel v1')),
);
final secret = setup.context.export(
  Uint8List.fromList(utf8.encode('quic-like secret')),
  32,
);
```

Export-only rejects `seal` and `open`. The other AEADs can both seal and
export on the same context.

Several messages on one context are ordered. The sender's nth `seal` is the
recipient's nth `open`.

## What was checked

The RFC 9180 published vectors for X25519 and P-256, all four modes,
HKDF-SHA256 and HKDF-SHA512, and every AEAD including export-only. One
X25519 / HKDF-SHA256 / AES-128-GCM base vector is checked through sequence
256. P-384 is a round trip in every mode and AEAD; that KEM is not in the
vector file pinned by the tests.

BoringSSL 0.20261020.0 `EVP_HPKE`, both directions:

- base and auth
- X25519 and P-256
- HKDF-SHA256 and HKDF-SHA384
- AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- `Export` of 32 bytes

`DeriveKeyPair` agrees with `EVP_HPKE_KEY_derive` for those two KEMs. The
BoringSSL public API has no PSK setup, no DHKEM(P-384), and no HKDF-SHA512,
so those are not part of the interop sentence. OpenSSL is not the HPKE peer.

The X25519 testing seed BoringSSL accepts is the ephemeral private key.
The P-256 testing seed is the `DeriveKeyPair` ikm. `PqHpke.setupSender`'s
`ephemeralIkm` is always the ikm, for every KEM. Leave it unset outside tests.

## The shape a TLS stack needs

[pqtransport](https://github.com/turkananation/pqtransport) ECH
(RFC 9849) uses base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and
AES-128-GCM. `info` is the ASCII string `tls ech` followed by a NUL and the
original ECHConfig bytes. That stack still composes those steps itself
until it depends on this release. The calls are `setupSender` /
`setupRecipient`, then one `seal` / `open`. No PSK. No auth mode.
