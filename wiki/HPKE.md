# HPKE

`PqHpke` is RFC 9180 Hybrid Public Key Encryption. The long form, with the
suite table and the BoringSSL sentence, is
[doc/protocols/HPKE.md](https://github.com/turkananation/pqforge/blob/main/doc/protocols/HPKE.md).

Modes: base, PSK, auth, authPSK.

KEMs: DHKEM(X25519, HKDF-SHA256), DHKEM(X448, HKDF-SHA512),
DHKEM(P-256, HKDF-SHA256), DHKEM(P-384, HKDF-SHA384),
DHKEM(P-521, HKDF-SHA512).

AEADs: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, and export-only.

A sender seals. A recipient opens. `export` does not use the sequence
number. A failed open does not advance it. This does not change `.pqf` or
`.pqfs`. It is not TLS and not a FIPS module. `PqX448` is not a
constant-time ladder.

BoringSSL 0.20261020.0 checks base and auth, both directions, for X25519
and P-256, HKDF-SHA256 and HKDF-SHA384, and the three AEADs. That API has
no PSK, no X448, and no P-521.

OpenSSL 3.5.9 checks all four modes, both directions, for X448 and P-521,
HKDF-SHA256 and HKDF-SHA512, and the three AEADs. That is not an OpenSSL
claim for X25519, P-256, or P-384.

```dart
import 'package:pqforge/pqforge.dart';

final recipient = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
final sealed = await PqHpke.seal(
  suite: HpkeSuite.x25519Aes128Gcm,
  mode: HpkeMode.base,
  recipientPublicKey: recipient.publicKey,
  plaintext: Uint8List.fromList(utf8.encode('the record')),
);
```
