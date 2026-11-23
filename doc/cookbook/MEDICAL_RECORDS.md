# Medical Records

Use `encryptRecord` with record type, record ID, and tenant/patient AAD. The
envelope metadata records the recipe and record identifiers; the AAD hash binds
external context without storing private context bytes directly. Confidentiality
is ML-KEM. It is not a signature.

Audit the access with `appendSignedLogEntry`. That log accepts ML-DSA or
SLH-DSA (`slhDsa:`). Enroll a clinician key with `createIdentityBinding` over
the same choice. Neither call belongs inside the `.pqf` header. A header
signature, if you add one, may be ML-DSA or HashSLH-DSA. The hash-based
signature is 8–50 KiB, so a small record usually keeps ML-DSA in the header
and puts SLH-DSA on the log and the identity binding.

You supply access control, audit logging policy, patient identity, retention
rules, and storage.
