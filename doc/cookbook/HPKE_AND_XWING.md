# HPKE And X-Wing

Use for a one-shot seal to a public key, or for a hybrid KEM shared
secret that is not PQXDH and not the custom combiner.

## RFC 9180

- Use: `PqHpke.seal`, `open`, `setupSender`, `setupRecipient`, `export`.
- Modes: base, PSK, auth, authPSK.
- KEMs: DHKEM X25519, X448, P-256, P-384, P-521.
- KDFs: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512. The KEM hash and the
  suite KDF are different knobs.
- AEADs: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, export-only.
- `export` does not move the sequence number. A failed open does not
  either. `dispose` scrubs the context. That is not a hard erasure claim.
- BoringSSL evidence is base and auth, X25519 and P-256. OpenSSL
  evidence is all four modes, X448 and P-521. There is no cross-claim
  for the other combinations.
- Not TLS, not a trust store, not a FIPS module. `.pqf` and `.pqfs`
  are unchanged.
- You supply the recipient public key's authenticity, replay policy,
  and `info` / associated data.

## X-Wing

- Use: `PqXWing` and, inside HPKE, `HpkeKem.xWing` (`0x647A`).
- One ML-KEM-768 encapsulation and one X25519. The shared secret is
  32 bytes from SHA3-256. The encapsulation key is 1216 bytes. The
  ciphertext is 1120 bytes.
- HPKE base and PSK work. Auth and authPSK throw.
- Not a FIPS construction. Not a `.pqf` algorithm. No BoringSSL or
  OpenSSL evidence for `0x647A`.
- Not PQXDH. A 32-byte `PqXWing.decapsulate` result can seed a
  `DoubleRatchet`. That composition is not this handshake.
- The custom hybrid (`PqForgeHybridKeyAgreement`) stays the default.
  Length must not choose between X-Wing and the TLS `X25519MLKEM768`
  concatenation. Those shared secrets are different sizes and different
  combiners.
- You supply which KEM the peer agreed to use.

See [../protocols/HPKE.md](../protocols/HPKE.md) and
[../protocols/XWING.md](../protocols/XWING.md).
