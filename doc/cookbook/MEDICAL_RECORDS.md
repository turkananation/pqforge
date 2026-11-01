# Medical Records

Use `encryptRecord` with record type, record ID, and tenant/patient AAD. The
envelope metadata records the recipe and record identifiers; the AAD hash binds
external context without storing private context bytes directly. Confidentiality
is ML-KEM. It is not a signature.

Audit the access with `appendSignedLogEntry`. That log accepts ML-DSA or
SLH-DSA (`slhDsa:`). Enroll a clinician key with `createIdentityBinding` over
the same choice. Neither call belongs inside the `.pqf` header. Envelope
signatures stay ML-DSA, and SLH-DSA signatures are large enough that they
should sit beside the record, not inside it.

You supply access control, audit logging policy, patient identity, retention
rules, and storage.
