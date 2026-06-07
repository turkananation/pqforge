# Threat Model

`pqforge` helps against:

- ciphertext disclosure when encrypted to an authenticated recipient key;
- payload tampering detected by AES-GCM;
- signature forgery under ML-DSA assumptions;
- accidental transcript ambiguity through length-prefixed messages;
- accidental key export exposure through passphrase wrapping.

`pqforge` does not solve:

- unauthenticated public keys;
- stolen endpoint devices;
- malicious app code;
- replay without an app replay store;
- broken passphrases;
- legal certification or compliance posture.
