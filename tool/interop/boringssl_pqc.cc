// BoringSSL driver for the parameter sets this pin exports.
//
// OpenSSL's EVP suite covers ML-KEM-512 and all 12 SLH-DSA sets. This
// BoringSSL does not. It exports ML-KEM-768 and ML-KEM-1024, ML-DSA-44/65/87,
// and SLH-DSA SHA2-128s and SHAKE-256f. The driver speaks those, and nothing
// else. Linked against libcrypto.a, which is C++.
//
// stdout is lowercase hex. A failure exits non-zero and writes nothing useful
// to stdout.

#include <openssl/bytestring.h>
#include <openssl/mlkem.h>
#include <openssl/mldsa.h>
#include <openssl/slhdsa.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

static void fail(const char *message) {
  fprintf(stderr, "boringssl_pqc: %s\n", message);
  exit(1);
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static std::vector<uint8_t> unhex(const char *text) {
  const size_t length = strlen(text);
  if (length % 2 != 0) fail("odd hex length");
  std::vector<uint8_t> out(length / 2);
  for (size_t i = 0; i < out.size(); i++) {
    const int hi = hex_nibble(text[2 * i]);
    const int lo = hex_nibble(text[2 * i + 1]);
    if (hi < 0 || lo < 0) fail("bad hex");
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return out;
}

static void print_hex(const uint8_t *bytes, size_t length) {
  for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
  printf("\n");
}

template <typename Public>
static std::vector<uint8_t> finish_public(
    int (*marshal)(CBB *, const Public *), const Public *key, size_t expect) {
  CBB cbb;
  if (!CBB_init(&cbb, expect) || !marshal(&cbb, key)) {
    CBB_cleanup(&cbb);
    fail("marshal");
  }
  uint8_t *data = nullptr;
  size_t length = 0;
  if (!CBB_finish(&cbb, &data, &length) || length != expect) {
    OPENSSL_free(data);
    fail("marshal length");
  }
  std::vector<uint8_t> out(data, data + length);
  OPENSSL_free(data);
  return out;
}

static void kem768_public(const std::vector<uint8_t> &seed) {
  if (seed.size() != MLKEM_SEED_BYTES) fail("seed");
  MLKEM768_private_key priv;
  MLKEM768_public_key pub;
  if (!MLKEM768_private_key_from_seed(&priv, seed.data(), seed.size())) {
    fail("seed");
  }
  MLKEM768_public_from_private(&pub, &priv);
  const auto encoded =
      finish_public(MLKEM768_marshal_public_key, &pub, MLKEM768_PUBLIC_KEY_BYTES);
  print_hex(encoded.data(), encoded.size());
}

static void kem1024_public(const std::vector<uint8_t> &seed) {
  if (seed.size() != MLKEM_SEED_BYTES) fail("seed");
  MLKEM1024_private_key priv;
  MLKEM1024_public_key pub;
  if (!MLKEM1024_private_key_from_seed(&priv, seed.data(), seed.size())) {
    fail("seed");
  }
  MLKEM1024_public_from_private(&pub, &priv);
  const auto encoded = finish_public(
      MLKEM1024_marshal_public_key, &pub, MLKEM1024_PUBLIC_KEY_BYTES);
  print_hex(encoded.data(), encoded.size());
}

static void kem768_encap(const std::vector<uint8_t> &pub_bytes) {
  if (pub_bytes.size() != MLKEM768_PUBLIC_KEY_BYTES) fail("public key");
  CBS cbs;
  CBS_init(&cbs, pub_bytes.data(), pub_bytes.size());
  MLKEM768_public_key pub;
  if (!MLKEM768_parse_public_key(&pub, &cbs)) fail("public key");
  uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t shared[MLKEM_SHARED_SECRET_BYTES];
  MLKEM768_encap(ciphertext, shared, &pub);
  print_hex(ciphertext, sizeof(ciphertext));
  print_hex(shared, sizeof(shared));
}

static void kem1024_encap(const std::vector<uint8_t> &pub_bytes) {
  if (pub_bytes.size() != MLKEM1024_PUBLIC_KEY_BYTES) fail("public key");
  CBS cbs;
  CBS_init(&cbs, pub_bytes.data(), pub_bytes.size());
  MLKEM1024_public_key pub;
  if (!MLKEM1024_parse_public_key(&pub, &cbs)) fail("public key");
  uint8_t ciphertext[MLKEM1024_CIPHERTEXT_BYTES];
  uint8_t shared[MLKEM_SHARED_SECRET_BYTES];
  MLKEM1024_encap(ciphertext, shared, &pub);
  print_hex(ciphertext, sizeof(ciphertext));
  print_hex(shared, sizeof(shared));
}

static void kem768_decap(const std::vector<uint8_t> &seed,
                          const std::vector<uint8_t> &ciphertext) {
  if (seed.size() != MLKEM_SEED_BYTES) fail("seed");
  if (ciphertext.size() != MLKEM768_CIPHERTEXT_BYTES) fail("ciphertext");
  MLKEM768_private_key priv;
  if (!MLKEM768_private_key_from_seed(&priv, seed.data(), seed.size())) {
    fail("seed");
  }
  uint8_t shared[MLKEM_SHARED_SECRET_BYTES];
  if (!MLKEM768_decap(shared, ciphertext.data(), ciphertext.size(), &priv)) {
    fail("decap");
  }
  print_hex(shared, sizeof(shared));
}

static void kem1024_decap(const std::vector<uint8_t> &seed,
                           const std::vector<uint8_t> &ciphertext) {
  if (seed.size() != MLKEM_SEED_BYTES) fail("seed");
  if (ciphertext.size() != MLKEM1024_CIPHERTEXT_BYTES) fail("ciphertext");
  MLKEM1024_private_key priv;
  if (!MLKEM1024_private_key_from_seed(&priv, seed.data(), seed.size())) {
    fail("seed");
  }
  uint8_t shared[MLKEM_SHARED_SECRET_BYTES];
  if (!MLKEM1024_decap(shared, ciphertext.data(), ciphertext.size(), &priv)) {
    fail("decap");
  }
  print_hex(shared, sizeof(shared));
}

template <typename Priv, typename Pub>
struct Dsa {
  int (*from_seed)(Priv *, const uint8_t *, size_t);
  int (*to_public)(Pub *, const Priv *);
  int (*marshal)(CBB *, const Pub *);
  int (*parse)(Pub *, CBS *);
  int (*sign)(uint8_t *, const Priv *, const uint8_t *, size_t, const uint8_t *,
              size_t);
  int (*verify)(const Pub *, const uint8_t *, size_t, const uint8_t *, size_t,
                const uint8_t *, size_t);
  size_t public_bytes;
  size_t signature_bytes;
};

template <typename Priv, typename Pub>
static void dsa_public(const Dsa<Priv, Pub> &ops, const std::vector<uint8_t> &seed) {
  if (seed.size() != MLDSA_SEED_BYTES) fail("seed");
  Priv priv;
  Pub pub;
  if (!ops.from_seed(&priv, seed.data(), seed.size()) ||
      !ops.to_public(&pub, &priv)) {
    fail("key");
  }
  const auto encoded = finish_public(ops.marshal, &pub, ops.public_bytes);
  print_hex(encoded.data(), encoded.size());
}

template <typename Priv, typename Pub>
static void dsa_sign(const Dsa<Priv, Pub> &ops, const std::vector<uint8_t> &seed,
                     const std::vector<uint8_t> &message,
                     const std::vector<uint8_t> &context) {
  if (seed.size() != MLDSA_SEED_BYTES) fail("seed");
  Priv priv;
  if (!ops.from_seed(&priv, seed.data(), seed.size())) fail("key");
  std::vector<uint8_t> signature(ops.signature_bytes);
  if (!ops.sign(signature.data(), &priv, message.data(), message.size(),
                context.data(), context.size())) {
    fail("sign");
  }
  print_hex(signature.data(), signature.size());
}

template <typename Priv, typename Pub>
static void dsa_verify(const Dsa<Priv, Pub> &ops,
                       const std::vector<uint8_t> &public_key,
                       const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &message,
                       const std::vector<uint8_t> &context) {
  if (public_key.size() != ops.public_bytes) fail("public key");
  CBS cbs;
  CBS_init(&cbs, public_key.data(), public_key.size());
  Pub pub;
  if (!ops.parse(&pub, &cbs)) fail("public key");
  const int ok = ops.verify(&pub, signature.data(), signature.size(),
                            message.data(), message.size(), context.data(),
                            context.size());
  printf("%s\n", ok ? "ok" : "fail");
}

static const Dsa<MLDSA44_private_key, MLDSA44_public_key> kDsa44 = {
    MLDSA44_private_key_from_seed,
    MLDSA44_public_from_private,
    MLDSA44_marshal_public_key,
    MLDSA44_parse_public_key,
    MLDSA44_sign,
    MLDSA44_verify,
    MLDSA44_PUBLIC_KEY_BYTES,
    MLDSA44_SIGNATURE_BYTES,
};

static const Dsa<MLDSA65_private_key, MLDSA65_public_key> kDsa65 = {
    MLDSA65_private_key_from_seed,
    MLDSA65_public_from_private,
    MLDSA65_marshal_public_key,
    MLDSA65_parse_public_key,
    MLDSA65_sign,
    MLDSA65_verify,
    MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
};

static const Dsa<MLDSA87_private_key, MLDSA87_public_key> kDsa87 = {
    MLDSA87_private_key_from_seed,
    MLDSA87_public_from_private,
    MLDSA87_marshal_public_key,
    MLDSA87_parse_public_key,
    MLDSA87_sign,
    MLDSA87_verify,
    MLDSA87_PUBLIC_KEY_BYTES,
    MLDSA87_SIGNATURE_BYTES,
};

static void slh_public(const char *which, const std::vector<uint8_t> &seed) {
  if (strcmp(which, "sha2-128s") == 0) {
    if (seed.size() != SLHDSA_SHA2_128S_SEED_BYTES) fail("seed");
    uint8_t public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES];
    uint8_t private_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES];
    SLHDSA_SHA2_128S_generate_key_from_seed(public_key, private_key, seed.data());
    print_hex(public_key, sizeof(public_key));
    return;
  }
  if (strcmp(which, "shake-256f") == 0) {
    if (seed.size() != SLHDSA_SHAKE_256F_SEED_BYTES) fail("seed");
    uint8_t public_key[SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES];
    uint8_t private_key[SLHDSA_SHAKE_256F_PRIVATE_KEY_BYTES];
    SLHDSA_SHAKE_256F_generate_key_from_seed(public_key, private_key, seed.data());
    print_hex(public_key, sizeof(public_key));
    return;
  }
  fail("unknown slh set");
}

static void slh_sign(const char *which, const std::vector<uint8_t> &seed,
                     const std::vector<uint8_t> &message,
                     const std::vector<uint8_t> &context) {
  if (strcmp(which, "sha2-128s") == 0) {
    if (seed.size() != SLHDSA_SHA2_128S_SEED_BYTES) fail("seed");
    uint8_t public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES];
    uint8_t private_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES];
    SLHDSA_SHA2_128S_generate_key_from_seed(public_key, private_key, seed.data());
    uint8_t signature[SLHDSA_SHA2_128S_SIGNATURE_BYTES];
    if (!SLHDSA_SHA2_128S_sign(signature, private_key, message.data(),
                               message.size(), context.data(), context.size())) {
      fail("sign");
    }
    print_hex(signature, sizeof(signature));
    return;
  }
  if (strcmp(which, "shake-256f") == 0) {
    if (seed.size() != SLHDSA_SHAKE_256F_SEED_BYTES) fail("seed");
    uint8_t public_key[SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES];
    uint8_t private_key[SLHDSA_SHAKE_256F_PRIVATE_KEY_BYTES];
    SLHDSA_SHAKE_256F_generate_key_from_seed(public_key, private_key, seed.data());
    uint8_t signature[SLHDSA_SHAKE_256F_SIGNATURE_BYTES];
    if (!SLHDSA_SHAKE_256F_sign(signature, private_key, message.data(),
                                message.size(), context.data(),
                                context.size())) {
      fail("sign");
    }
    print_hex(signature, sizeof(signature));
    return;
  }
  fail("unknown slh set");
}

static void slh_verify(const char *which, const std::vector<uint8_t> &public_key,
                       const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &message,
                       const std::vector<uint8_t> &context) {
  int ok = 0;
  if (strcmp(which, "sha2-128s") == 0) {
    if (public_key.size() != SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES) fail("public key");
    ok = SLHDSA_SHA2_128S_verify(public_key.data(), signature.data(),
                                 signature.size(), message.data(), message.size(),
                                 context.data(), context.size());
  } else if (strcmp(which, "shake-256f") == 0) {
    if (public_key.size() != SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES) fail("public key");
    ok = SLHDSA_SHAKE_256F_verify(public_key.data(), signature.data(),
                                  signature.size(), message.data(),
                                  message.size(), context.data(), context.size());
  } else {
    fail("unknown slh set");
  }
  printf("%s\n", ok ? "ok" : "fail");
}

int main(int argc, char **argv) {
  if (argc < 2) fail("no command");
  const std::string command = argv[1];
  if (command == "kem-public" && argc == 4) {
    const auto seed = unhex(argv[3]);
    if (strcmp(argv[2], "768") == 0) kem768_public(seed);
    else if (strcmp(argv[2], "1024") == 0) kem1024_public(seed);
    else fail("level");
    return 0;
  }
  if (command == "kem-encap" && argc == 4) {
    const auto pub = unhex(argv[3]);
    if (strcmp(argv[2], "768") == 0) kem768_encap(pub);
    else if (strcmp(argv[2], "1024") == 0) kem1024_encap(pub);
    else fail("level");
    return 0;
  }
  if (command == "kem-decap" && argc == 5) {
    const auto seed = unhex(argv[3]);
    const auto ct = unhex(argv[4]);
    if (strcmp(argv[2], "768") == 0) kem768_decap(seed, ct);
    else if (strcmp(argv[2], "1024") == 0) kem1024_decap(seed, ct);
    else fail("level");
    return 0;
  }
  if (command == "dsa-public" && argc == 4) {
    const auto seed = unhex(argv[3]);
    if (strcmp(argv[2], "44") == 0) dsa_public(kDsa44, seed);
    else if (strcmp(argv[2], "65") == 0) dsa_public(kDsa65, seed);
    else if (strcmp(argv[2], "87") == 0) dsa_public(kDsa87, seed);
    else fail("level");
    return 0;
  }
  if (command == "dsa-sign" && argc == 6) {
    const auto seed = unhex(argv[3]);
    const auto message = unhex(argv[4]);
    const auto context = unhex(argv[5]);
    if (strcmp(argv[2], "44") == 0) dsa_sign(kDsa44, seed, message, context);
    else if (strcmp(argv[2], "65") == 0) dsa_sign(kDsa65, seed, message, context);
    else if (strcmp(argv[2], "87") == 0) dsa_sign(kDsa87, seed, message, context);
    else fail("level");
    return 0;
  }
  if (command == "dsa-verify" && argc == 7) {
    const auto pub = unhex(argv[3]);
    const auto sig = unhex(argv[4]);
    const auto message = unhex(argv[5]);
    const auto context = unhex(argv[6]);
    if (strcmp(argv[2], "44") == 0) dsa_verify(kDsa44, pub, sig, message, context);
    else if (strcmp(argv[2], "65") == 0) dsa_verify(kDsa65, pub, sig, message, context);
    else if (strcmp(argv[2], "87") == 0) dsa_verify(kDsa87, pub, sig, message, context);
    else fail("level");
    return 0;
  }
  if (command == "slh-public" && argc == 4) {
    slh_public(argv[2], unhex(argv[3]));
    return 0;
  }
  if (command == "slh-sign" && argc == 6) {
    slh_sign(argv[2], unhex(argv[3]), unhex(argv[4]), unhex(argv[5]));
    return 0;
  }
  if (command == "slh-verify" && argc == 7) {
    slh_verify(argv[2], unhex(argv[3]), unhex(argv[4]), unhex(argv[5]),
               unhex(argv[6]));
    return 0;
  }
  fail("usage");
}
