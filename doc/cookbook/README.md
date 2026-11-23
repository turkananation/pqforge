# pqforge Cookbook

The cookbook maps high-level product needs to tested package APIs:

- file encryption;
- folder encryption;
- text encryption and signing;
- media encryption and signing;
- document signing;
- government records;
- medical records;
- webhooks and tokens;
- signed logs;
- software artifacts;
- identity bindings;
- hybrid session derivation;
- direct conversations;
- HPKE and X-Wing.

Start with [PROJECT_CATALOG.md](PROJECT_CATALOG.md) when you know the app you
want to build. Use [../CLI.md](../CLI.md) when you need local or server command
line workflows.

Every recipe follows the same rule: state what `pqforge` provides, state what
the app supplies, then state the caveat.

Detached signatures accept ML-DSA or SLH-DSA. Pass `slhDsa:` (and not `algorithm`)
for a hash-based key from `keygen`. That covers documents, text, media, webhooks,
artifacts, tokens, signed logs, and identity bindings. The same key can sign an
envelope or a `.pqfs` header once, as HashSLH-DSA over the existing digest, and
it can be the post-quantum leg of `hybrid-sign` (JSON version 2). An ML-DSA
secret still signs with ML-DSA. X.509 stays ML-DSA. An SLH-DSA signature is
8–50 KiB. The `s` sets are slow; naming one allows it. Use `--digest` for a
large hybrid signature.

`compose-sign` is the multi-algorithm signature. Pass 2 or 3 of
`--ml-dsa-secret`, `--slh-secret`, and repeatable `--classical-secret`
(Ed25519, ECDSA-P256, ECDSA-P384, ECDSA-P521). Nothing is added for you.
`require-all` is the default. ECDSA-P384 and ECDSA-P521 are
`keygen --classical` opt-ins, not the default key set. `hybrid-sign` is one post-quantum leg plus one classical leg. The post-quantum
leg is ML-DSA (version 1) or SLH-DSA (version 2).

## Recipe Docs

| Need | Document |
| --- | --- |
| File and folder encryption | [FILE_ENCRYPTION.md](FILE_ENCRYPTION.md) |
| Text, media, and folder recipe APIs | [TEXT_MEDIA_AND_FOLDERS.md](TEXT_MEDIA_AND_FOLDERS.md) |
| Documents | [DOCUMENT_SIGNING.md](DOCUMENT_SIGNING.md) |
| Webhooks and tokens | [WEBHOOKS_AND_TOKENS.md](WEBHOOKS_AND_TOKENS.md) |
| Government records | [GOVERNMENT_RECORDS.md](GOVERNMENT_RECORDS.md) |
| Medical records | [MEDICAL_RECORDS.md](MEDICAL_RECORDS.md) |
| Direct conversations | [CONVERSATIONS.md](CONVERSATIONS.md) |
| HPKE and X-Wing | [HPKE_AND_XWING.md](HPKE_AND_XWING.md) |
