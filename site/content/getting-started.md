---
title: Getting started
description: Install pqforge and seal one HPKE message.
---

```yaml
dependencies:
  pqforge: ^0.4.13
```

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

Future<void> main() async {
  final recipient = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
  final sealed = await PqHpke.seal(
    suite: HpkeSuite.x25519Aes128Gcm,
    mode: HpkeMode.base,
    recipientPublicKey: recipient.publicKey,
    info: Uint8List.fromList(utf8.encode('app message v1')),
    plaintext: Uint8List.fromList(utf8.encode('the record')),
  );
  final opened = await PqHpke.open(
    suite: HpkeSuite.x25519Aes128Gcm,
    mode: HpkeMode.base,
    enc: sealed.enc,
    ciphertext: sealed.ciphertext,
    recipientKey: recipient,
    info: Uint8List.fromList(utf8.encode('app message v1')),
  );
  print(utf8.decode(opened.plaintext));
}
```

Send `enc` and `ciphertext`. Keep `recipient.secretKey` off the wire.
`info` is bound into the key schedule: a different info string does not
open the same ciphertext.

The CLI is still `dart run pqforge`. `keygen`, `encrypt`, `sign`, and
`cert` are unchanged by HPKE. HPKE is a library API, not a new envelope
format.

Signatures in this same release are a separate surface. `sign --kind webhook`,
`compose-sign`, and `keygen --classical ecdsa-p384` / `ecdsa-p521` do not
change the HPKE calls above. The page for those legs is [Signatures](signatures).
P-521 as an HPKE KEM is unchanged.
