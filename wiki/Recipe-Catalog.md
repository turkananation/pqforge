# Recipe Catalog

Use these mappings when deciding which pqforge surface fits an application.

| App | Surface |
| --- | --- |
| Local file vault | `encrypt`, `decrypt`, `encryptFileBytes` |
| Folder archive | `encrypt-folder`, `decrypt-folder`, `encryptFolderEntry` |
| Text note or secret | `encrypt-text`, `decrypt-text`, `sealText`, `signText` |
| Media archive | `encrypt-media`, `decrypt-media`, `sealMedia`, `signMedia` |
| Contract or report | `sign --kind document`, `signDocument` |
| Webhook system | `signWebhook`, `verifyWebhook` |
| Capability token issuer | `issueToken`, `verifyToken` |
| Email payload protection | `sealEmail`, `openEmail` |
| Government or medical records | `encryptRecord`, `appendSignedLogEntry` |
| Software release signing | `sign --kind artifact`, `signArtifact` |
| Server session bootstrap | `PqForgeHybridKeyAgreement`, `PqForgeSecureSession` |

Every recipe binds a domain label and purpose-specific metadata into a canonical
message or AAD value. That prevents a valid signature or envelope from being
silently reused as a different kind of object.
