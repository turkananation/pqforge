# CLI Guide

The CLI supports reusable keys, wrapped secret keys, file encryption, folder
encryption, text encryption, media encryption, and recipe-specific signatures.

## Wrapped Keys

```bash
export PQFORGE_PASSPHRASE='load-this-from-a-secret-manager'
dart run pqforge keygen --profile maximum --key-id vault --out-dir keys --passphrase-env PQFORGE_PASSPHRASE
```

Public keys:

- `vault.kem.public.json`
- `vault.sign.public.json`

Wrapped secret keys:

- `vault.kem.secret.wrapped.json`
- `vault.sign.secret.wrapped.json`

## Files

```bash
dart run pqforge encrypt --recipient-public keys/vault.kem.public.json --in report.pdf --out report.pdf.pqf
dart run pqforge decrypt --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in report.pdf.pqf --out report.open.pdf
```

## Folders

```bash
dart run pqforge encrypt-folder --recipient-public keys/vault.kem.public.json --in-dir ./records --out-dir ./records.pqf
dart run pqforge decrypt-folder --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in-dir ./records.pqf --out-dir ./records.open
```

## Text

```bash
dart run pqforge encrypt-text --recipient-public keys/vault.kem.public.json --text 'private memo' --text-id memo-1 --out memo.pqf
dart run pqforge decrypt-text --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in memo.pqf
```

## Media

```bash
dart run pqforge encrypt-media --recipient-public keys/vault.kem.public.json --in cover.png --mime-type image/png --out cover.png.pqf
dart run pqforge decrypt-media --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in cover.png.pqf --out cover.open.png
```

## Signatures

```bash
dart run pqforge sign --signer-secret keys/vault.sign.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --kind media --in cover.png --mime-type image/png --out cover.sig.json
dart run pqforge verify --signer-public keys/vault.sign.public.json --in cover.png --signature cover.sig.json
```
