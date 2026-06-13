# Recipe Catalog

Use these mappings when deciding which `pqforge` surface fits an application.

| App | Surface |
| --- | --- |
| Local file vault | `encrypt`, `decrypt`, `encryptFileBytes` |
| Folder archive (per file) | `encrypt-folder`, `decrypt-folder`, `encryptFolderEntry` |
| Whole-folder archive (one file) | `pack`, `unpack`, `PqForgePackService` |
| Gigabyte files and media | `encrypt`/`encrypt-media` (auto `.pqfs`), `PqForgeStreamCipher` |
| One ciphertext for many readers | repeatable `--recipient-public`, `PqMultiRecipient` |
| Defence-in-depth at rest (PQC + classical) | `encrypt --hybrid`, `encryptAsync` |
| Text note or secret | `encrypt-text`, `decrypt-text`, `sealText`, `signText` |
| Media archive | `encrypt-media`, `decrypt-media`, `sealMedia`, `signMedia` |
| Contract or report | `sign --kind document`, `signDocument` |
| Webhook system | `signWebhook`, `verifyWebhook` |
| Capability token issuer | `issueToken`, `verifyToken` |
| Email payload protection | `sealEmail`, `openEmail` |
| Government or medical records | `encryptRecord`, `appendSignedLogEntry` |
| Software release signing | `sign --kind artifact`, `signArtifact` |
| Release/firmware dual signing | `hybrid-sign`/`hybrid-verify`, `PqForgeHybridSigner` |
| Standalone classical signing | `ecdsa-sign`/`ecdsa-verify`, `PqEcdsaP256` |
| Server session bootstrap | `PqForgeHybridKeyAgreement`, `PqForgeSecureSession` |

Every recipe binds a domain label and purpose-specific metadata into a canonical
message or AAD value. That prevents a valid signature or envelope from being
silently reused as a different kind of object.

For large-file and multi-recipient mechanics see
[Streaming And Large Files](Streaming-And-Large-Files) and
[Multi-Recipient And Hybrid](Multi-Recipient-And-Hybrid). The full app-to-recipe
catalog is in
[doc/cookbook/PROJECT_CATALOG.md](https://github.com/turkananation/pqforge/blob/main/doc/cookbook/PROJECT_CATALOG.md).
