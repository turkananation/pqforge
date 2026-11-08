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
  0.4.12 adds `PqBrainpool` and `PqFfdhe`: the three brainpool TLS groups
  and the five RFC 7919 finite-field groups. Agreement only. Not a TLS
  stack, and not constant-time. 0.4.11 adds `PqBytes.sha1` (RFC 3174).
  Collision resistance is broken. It is there for a standard that still
  names SHA-1, such as DNSSEC NSEC3. It is not a signature. 0.4.10 adds
  RFC 9180 HPKE. 0.4.9 is X.509 and the classical signatures those
  certificates use. 0.4.8 is the ChaCha20 keystream. None of those
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
| 0.4.12 | `PqBrainpool` and `PqFfdhe`. brainpoolP256r1, P384r1, P512r1, and ffdhe2048 through ffdhe8192. |
| 0.4.11 | `PqBytes.sha1` and `sha1OfStream`. RFC 3174, 20 bytes. Not for a new protocol. |
| 0.4.10 | `PqHpke` — base, PSK, auth, authPSK. X25519, X448, P-256, P-384, P-521. AES-GCM and ChaCha20-Poly1305. |
| 0.4.10 | Signature legs. `slhDsa:` on detached recipes. `compose-sign` for a dual or a triple. Opt-in ECDSA-P384 and ECDSA-P521. See [Signatures](signatures). |
| 0.4.9 | `PqX509`, `PqEcdsaP384`, `PqRsa`, `PqEd25519`, and `pqforge cert`. |
| 0.4.8 | `PqSymmetricPrimitives.chacha20` — RFC 8439 keystream, including a QUIC header-protection mask. |

The rest of the package is unchanged in role: ML-KEM envelopes, ML-DSA and
SLH-DSA detached signatures, hybrid sessions, multi-recipient envelopes,
Argon2id key custody, and the CLI.

The same 0.4.10 release also widens signatures. That does not change the
HPKE row above. [Signatures](signatures) has the new legs:
`slhDsa:` on the detached recipes, `compose-sign` for a dual or a triple,
and opt-in ECDSA-P384 / ECDSA-P521. P-521 ECDH on the [Classical](classical)
page is still the HPKE share, not that signature.

[HPKE use cases](hpke) · [Certificates](certificates) · [Symmetric](symmetric) · [Classical](classical) · [Signatures](signatures) · [Claim boundary](claim-boundary)
