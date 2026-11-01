---
title: pqforge
description: Post-quantum application crypto for Dart and Flutter. HPKE, envelopes, certificates, and a CLI, on pqcrypto.
---

pqforge is the application layer on
[pqcrypto](https://pub.dev/packages/pqcrypto).
The primitives stay there. This package is what you call when a program has
to seal a record, sign a release, wrap a key, mint a certificate, or run
HPKE.

<Info>
  0.4.10 adds RFC 9180 HPKE. 0.4.9 is X.509 and the classical signatures
  those certificates use. 0.4.8 is the ChaCha20 keystream. None of those
  changed the `.pqf` or `.pqfs` wire format. Not a FIPS 140 module.
</Info>

```dart
import 'package:pqforge/pqforge.dart';
```

That import is pure Dart. No `dart:ffi` on the path, so the same library
runs on the Dart VM, Flutter, and the web. File streaming that needs
`dart:io` is `package:pqforge/pqforge_io.dart`.

## What landed and was easy to miss

| Release | You can call |
| --- | --- |
| 0.4.10 | `PqHpke` — base, PSK, auth, authPSK. X25519, P-256, P-384. AES-GCM and ChaCha20-Poly1305. |
| 0.4.9 | `PqX509`, `PqEcdsaP384`, `PqRsa`, `PqEd25519`, and `pqforge cert`. |
| 0.4.8 | `PqSymmetricPrimitives.chacha20` — RFC 8439 keystream, including a QUIC header-protection mask. |

The rest of the package is unchanged in role: ML-KEM envelopes, ML-DSA and
SLH-DSA detached signatures, hybrid sessions, multi-recipient envelopes,
Argon2id key custody, and the CLI.

[HPKE use cases](hpke) · [Certificates](certificates) · [Symmetric](symmetric) · [Claim boundary](claim-boundary)
