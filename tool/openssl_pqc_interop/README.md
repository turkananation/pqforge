# OpenSSL interoperability

This is the pqcrypto OpenSSL suite, ported so pqforge's CI runs it against
the OpenSSL 4.1.0 pin in `tool/interop/pins.env`. It is not published.

It checks the `pqcrypto` 0.4.4 bytes pqforge depends on:

- ML-KEM-512/768/1024, both directions, seeded keys, and implicit rejection
- ML-DSA-44/65/87 seeded keys and hedged pure signatures
- all 12 SLH-DSA parameter sets, seeded keys, internal and external signatures

```bash
sh tool/interop/build_pinned.sh
cd tool/openssl_pqc_interop
dart pub get
LIBCRYPTO_PATH=../interop/.build/openssl/lib/libcrypto.so \
  dart test --concurrency=1
```

A missing library skips the tests. CI sets `LIBCRYPTO_PATH` and treats a
missing library as a failure. This is independent implementation evidence,
not a FIPS 140 validation claim.
