# Webhooks and Tokens

Use `signWebhook` / `verifyWebhook` to bind event type, timestamp, and payload
hash into a signed message. Use `issueToken` / `verifyToken` for signed API or
capability tokens with canonical JSON claims.

You supply timestamp windows, nonce/replay rejection, token schemas, revocation,
and key publication.
