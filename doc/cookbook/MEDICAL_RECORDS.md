# Medical Records

Use `encryptRecord` with record type, record ID, and tenant/patient AAD. The
envelope metadata records the recipe and record identifiers; the AAD hash binds
external context without storing private context bytes directly.

You supply access control, audit logging policy, patient identity, retention
rules, and storage.
