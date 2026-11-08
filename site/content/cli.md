---
title: CLI
description: Every pqforge command, and which API it calls.
---

The executable is `dart run pqforge`, or `pqforge` after you activate the
package. `version` prints `0.4.12` from `bin/src/version.g.dart`, which is
generated from the `version:` field in `pubspec.yaml`. Those two are not
allowed to drift. CI checks the generator.

Secrets on disk are wrapped. Pass the passphrase with
`--passphrase-env NAME`, not on the command line.

## Commands

| Command | What it calls |
| --- | --- |
| `keygen` | `generateKeys`, plus classical keys unless `--no-classical`. Writes public JSON and a wrapped secret. |
| `inspect` | Reads a key, an envelope, or a certificate and prints the algorithm, the profile, and the lengths. It does not unwrap. |
| `encrypt` / `decrypt` | One ML-KEM envelope. Extra `--recipient-public` values become `PqMultiRecipient` wraps. |
| `encrypt-folder` / `decrypt-folder` | One sealed tree. Each file is `encryptFolderEntry`. |
| `encrypt-text` / `decrypt-text` | `sealText` / `openText`. |
| `encrypt-media` / `decrypt-media` | `sealMedia` / `openMedia`. |
| `pack` / `unpack` | A folder archive of already-sealed entries. |
| `sign` / `verify` | Detached ML-DSA, or SLH-DSA when you pass `--slh-dsa`. |
| `hybrid-sign` / `hybrid-verify` | One ML-DSA leg plus one classical leg. The classical leg is Ed25519 or ECDSA. |
| `compose-sign` / `compose-verify` | Opt-in dual or triple. `accept-any` or require every leg. |
| `ecdsa-sign` / `ecdsa-verify` | `PqEcdsaP256`, `PqEcdsaP384`, or an opted-in `PqEcdsaP521`. |
| `cert` | `PqX509` request, issue, and sign. The shape OpenSSL `req` reads. |
| `version` | The generated CLI version. |
| `uninstall` | Removes the activated executable. It does not delete keys. |

## keygen

`--profile` is `compact`, `balanced`, or `maximum`. See
[Envelopes](envelopes) for the sets. `--kem` and `--sig` override the pair
inside that profile. `--slh-dsa` picks one of the 12 sets. Omit it and the
profile's default is used: SHAKE-128f, SHAKE-192f, or SHAKE-256f.

Classical keys are on by default: X25519, and the ECDSA curves the profile
mints. `--no-classical` skips them. `--classical ecdsa-p521` opts into the
P-521 signature key. That key is not the P-521 HPKE share.

`--key-id` is the id bound into the wrap associated data. The public files
are named from that id. The secret file is the wrapped JSON from
[Keys](keys).

## encrypt

`--recipient-public` is an ML-KEM public JSON file. The first one is the
primary. Further ones can open the same DEM key without holding the
primary secret. `--profile` must be a profile the recipient key can
decapsulate. A compact public key does not open a maximum envelope.

`--in` and `--out` are files. At 8 MiB and above, `encrypt` writes a
`.pqfs` streaming envelope. Below that it writes one `.pqf`. Decrypt
takes `--recipient-secret` and the same passphrase env. `cmp` against the
original is the check the CI smoke uses.

## sign

`sign` hashes or takes the message, then writes a detached signature.
`verify` needs the public key, the message, and the signature. A context
string, when the command accepts one, is the FIPS 204 context. It is not
encrypted. An empty context and a missing context are the same only when
both sides omit it. Do not mix them.

`hybrid-sign` fails closed unless both legs verify. `compose-verify`
follows the policy stored with the signature: every leg, or any one leg.
A composite is not an envelope signature.

`cert req` is `openssl req`. `cert issue` is the issuer path. The subject
and the SAN use OpenSSL's `-subj` and `-addext` syntax. See
[Certificates](certificates).

[Getting started](getting-started) · [Signatures](signatures) · [Agreement](agreement)
