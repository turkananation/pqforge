# pqforge CLI Guide

The `pqforge` executable is for local machines, server jobs, release pipelines,
and admin workflows that need post-quantum encryption or signatures without
writing an app first.

Install from this package with:

```bash
dart pub global activate --source path .
```

Or run directly inside the repository:

```bash
dart run pqforge --help
```

## Key Storage

`keygen` writes reusable keys into the directory passed to `--out-dir`.

Public keys are not secret:

- `<key-id>.kem.public.json`
- `<key-id>.sign.public.json`

Secret keys should be wrapped:

- `<key-id>.kem.secret.wrapped.json`
- `<key-id>.sign.secret.wrapped.json`

Wrapped secret keys use `PqWrappedKey`: Argon2id derives a wrapping key from the
passphrase, and AES-256-GCM encrypts the secret key bytes with authenticated
metadata.

```bash
export PQFORGE_PASSPHRASE='load-this-from-a-secret-manager'
dart run pqforge keygen \
  --profile maximum \
  --key-id vault \
  --out-dir keys \
  --passphrase-env PQFORGE_PASSPHRASE
```

Passphrase sources:

| Option | Use |
| --- | --- |
| `--passphrase-env NAME` | CI/server jobs where `NAME` is populated by a secret manager |
| `--passphrase-file path` | Local scripts that read from protected files |
| `--passphrase value` | Short-lived testing only; it can leak through shell history |

If no passphrase source is supplied, `keygen` writes raw secret-key JSON and
prints a warning. Use raw secret files only for disposable tests.

## File Encryption

```bash
dart run pqforge encrypt \
  --recipient-public keys/vault.kem.public.json \
  --profile maximum \
  --in report.pdf \
  --out report.pdf.pqf

dart run pqforge decrypt \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in report.pdf.pqf \
  --out report.open.pdf
```

The file name is bound into structured `pqforge/file/v1` AAD. If you pass
`--aad`, that value is also bound into the envelope and must be supplied again
for decryption.

## Folder Encryption

Folder encryption writes one `.pqf` envelope per file and preserves relative
paths.

```bash
dart run pqforge encrypt-folder \
  --recipient-public keys/vault.kem.public.json \
  --profile maximum \
  --in-dir ./records \
  --out-dir ./records.pqf \
  --aad tenant:county-a

dart run pqforge decrypt-folder \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in-dir ./records.pqf \
  --out-dir ./records.open \
  --aad tenant:county-a
```

Each relative path is bound into `pqforge/folder-entry/v1` AAD, so a folder entry
cannot be moved to another path and still authenticate.

## Text Encryption

Use text commands for short UTF-8 strings, prompts, notes, and secrets.

```bash
dart run pqforge encrypt-text \
  --recipient-public keys/vault.kem.public.json \
  --text 'private memo' \
  --text-id memo-2026-001 \
  --out memo.pqf

dart run pqforge decrypt-text \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in memo.pqf
```

For larger text files:

```bash
dart run pqforge encrypt-text \
  --recipient-public keys/vault.kem.public.json \
  --in memo.txt \
  --text-id memo-2026-001 \
  --out memo.txt.pqf
```

## Media Encryption

Use media commands for images, audio, video, PDFs, and other content where MIME
type matters.

```bash
dart run pqforge encrypt-media \
  --recipient-public keys/vault.kem.public.json \
  --in cover.png \
  --media-id cover-2026-001 \
  --mime-type image/png \
  --out cover.png.pqf

dart run pqforge decrypt-media \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in cover.png.pqf \
  --out cover.open.png
```

If `--mime-type` is omitted, the CLI infers common extensions and otherwise
uses `application/octet-stream`.

## Signatures

The `sign` command supports recipe-specific signature containers.

```bash
dart run pqforge sign \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --kind document \
  --in contract.pdf \
  --document-id contract-2026-001 \
  --out contract.sig.json

dart run pqforge verify \
  --signer-public keys/vault.sign.public.json \
  --in contract.pdf \
  --signature contract.sig.json
```

Supported `--kind` values:

| Kind | Bound fields |
| --- | --- |
| `document` | document id, payload hash, payload length |
| `text` | text id, UTF-8 encoding, payload hash, payload length |
| `media` | media id, MIME type, payload hash, payload length |
| `artifact` | artifact id, version, artifact hash |

Media signing example:

```bash
dart run pqforge sign \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --kind media \
  --in cover.png \
  --media-id cover-2026-001 \
  --mime-type image/png \
  --out cover.sig.json

dart run pqforge verify \
  --signer-public keys/vault.sign.public.json \
  --in cover.png \
  --signature cover.sig.json
```

Artifact signing example:

```bash
dart run pqforge sign \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --kind artifact \
  --in release.tar.gz \
  --artifact-id pqforge-release \
  --version 7 \
  --out release.sig.json
```

## Signed Envelopes

Encryption commands accept `--signer-secret` to sign the encrypted envelope:

```bash
dart run pqforge encrypt \
  --recipient-public keys/vault.kem.public.json \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --signer-key-id vault-signer \
  --in report.pdf \
  --out report.signed.pqf
```

Decrypt signed envelopes with the signer public key:

```bash
dart run pqforge decrypt \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --signer-public keys/vault.sign.public.json \
  --in report.signed.pqf \
  --out report.open.pdf
```

## Operational Notes

- Keep wrapped secret-key JSON in a protected store.
- Prefer `--passphrase-env` for automation.
- Rotate keys according to the app's retention and risk policy.
- Keep public-key trust explicit; a self-provided public key is not an identity.
- Do not use this CLI as a streaming encryptor for multi-GB files yet; add
  application-level chunking for very large payloads.
