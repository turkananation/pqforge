/* BoringSSL EVP_HPKE peer for the pqforge HPKE flight.
   Linked against the pinned libcrypto. Prints hex on stdout. */
#include <openssl/err.h>
#include <openssl/hpke.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 2048

static void die(const char *message) {
  fprintf(stderr, "%s\n", message);
  ERR_print_errors_fp(stderr);
  exit(1);
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t max) {
  size_t n = strlen(hex);
  if (n % 2 != 0 || n / 2 > max) die("bad hex");
  for (size_t i = 0; i < n; i += 2) {
    int hi = hex_value(hex[i]);
    int lo = hex_value(hex[i + 1]);
    if (hi < 0 || lo < 0) die("bad hex digit");
    out[i / 2] = (uint8_t)((hi << 4) | lo);
  }
  return n / 2;
}

static void hex_print(const uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

static const EVP_HPKE_KEM *kem_of(const char *name) {
  if (strcmp(name, "x25519") == 0) return EVP_hpke_x25519_hkdf_sha256();
  if (strcmp(name, "p256") == 0) return EVP_hpke_p256_hkdf_sha256();
  die("unknown kem");
  return NULL;
}

static const EVP_HPKE_KDF *kdf_of(const char *name) {
  if (strcmp(name, "sha256") == 0) return EVP_hpke_hkdf_sha256();
  if (strcmp(name, "sha384") == 0) return EVP_hpke_hkdf_sha384();
  die("unknown kdf");
  return NULL;
}

static const EVP_HPKE_AEAD *aead_of(const char *name) {
  if (strcmp(name, "aes128") == 0) return EVP_hpke_aes_128_gcm();
  if (strcmp(name, "aes256") == 0) return EVP_hpke_aes_256_gcm();
  if (strcmp(name, "chacha") == 0) return EVP_hpke_chacha20_poly1305();
  die("unknown aead");
  return NULL;
}

static EVP_HPKE_KEY *key_from_seed(const EVP_HPKE_KEM *kem, const uint8_t *sk,
                                   size_t sk_len) {
  EVP_HPKE_KEY *key = EVP_HPKE_KEY_new();
  if (key == NULL || !EVP_HPKE_KEY_init(key, kem, sk, sk_len)) {
    die("EVP_HPKE_KEY_init failed");
  }
  return key;
}

static int cmd_derive(int argc, char **argv) {
  if (argc != 4) die("usage: derive kem ikm_hex");
  const EVP_HPKE_KEM *kem = kem_of(argv[2]);
  uint8_t ikm[MAX_BUF];
  size_t ikm_len = hex_decode(argv[3], ikm, sizeof(ikm));
  EVP_HPKE_KEY *key = EVP_HPKE_KEY_new();
  if (key == NULL || !EVP_HPKE_KEY_derive(key, kem, ikm, ikm_len)) {
    die("EVP_HPKE_KEY_derive failed");
  }
  uint8_t sk[256], pk[256];
  size_t sk_len = 0, pk_len = 0;
  if (!EVP_HPKE_KEY_private_key(key, sk, &sk_len, sizeof(sk)) ||
      !EVP_HPKE_KEY_public_key(key, pk, &pk_len, sizeof(pk))) {
    die("key export failed");
  }
  hex_print(sk, sk_len);
  printf(" ");
  hex_print(pk, pk_len);
  printf("\n");
  EVP_HPKE_KEY_free(key);
  return 0;
}

static void export_and_print(EVP_HPKE_CTX *ctx, const uint8_t *enc,
                             size_t enc_len, const uint8_t *body, size_t body_len,
                             const uint8_t *exp_ctx, size_t exp_ctx_len,
                             size_t exp_len) {
  uint8_t exported[256];
  if (exp_len > sizeof(exported) ||
      !EVP_HPKE_CTX_export(ctx, exported, exp_len, exp_ctx, exp_ctx_len)) {
    die("export failed");
  }
  if (enc != NULL) {
    hex_print(enc, enc_len);
    printf(" ");
  }
  hex_print(body, body_len);
  printf(" ");
  hex_print(exported, exp_len);
  printf("\n");
}

static int cmd_base_seal(int argc, char **argv) {
  /* base-seal kem kdf aead pkR info aad pt expctx explen [seed] */
  if (argc != 11 && argc != 12) die("usage: base-seal");
  const EVP_HPKE_KEM *kem = kem_of(argv[2]);
  const EVP_HPKE_KDF *kdf = kdf_of(argv[3]);
  const EVP_HPKE_AEAD *aead = aead_of(argv[4]);
  uint8_t pk[256], info[MAX_BUF], aad[MAX_BUF], pt[MAX_BUF], exp_ctx[MAX_BUF],
      seed[256], enc[256], ct[MAX_BUF];
  size_t pk_len = hex_decode(argv[5], pk, sizeof(pk));
  size_t info_len = hex_decode(argv[6], info, sizeof(info));
  size_t aad_len = hex_decode(argv[7], aad, sizeof(aad));
  size_t pt_len = hex_decode(argv[8], pt, sizeof(pt));
  size_t exp_ctx_len = hex_decode(argv[9], exp_ctx, sizeof(exp_ctx));
  size_t exp_len = (size_t)strtoul(argv[10], NULL, 10);
  size_t seed_len = argc == 12 ? hex_decode(argv[11], seed, sizeof(seed)) : 0;
  EVP_HPKE_CTX *ctx = EVP_HPKE_CTX_new();
  size_t enc_len = 0;
  int ok = seed_len
               ? EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
                     ctx, enc, &enc_len, sizeof(enc), kem, kdf, aead, pk, pk_len,
                     info, info_len, seed, seed_len)
               : EVP_HPKE_CTX_setup_sender(ctx, enc, &enc_len, sizeof(enc), kem,
                                           kdf, aead, pk, pk_len, info, info_len);
  if (!ok) die("setup_sender failed");
  size_t ct_len = 0;
  if (!EVP_HPKE_CTX_seal(ctx, ct, &ct_len, sizeof(ct), pt, pt_len, aad,
                         aad_len)) {
    die("seal failed");
  }
  export_and_print(ctx, enc, enc_len, ct, ct_len, exp_ctx, exp_ctx_len, exp_len);
  EVP_HPKE_CTX_free(ctx);
  return 0;
}

static int cmd_base_open(int argc, char **argv) {
  /* base-open kem kdf aead skR enc info aad ct expctx explen */
  if (argc != 12) die("usage: base-open");
  const EVP_HPKE_KEM *kem = kem_of(argv[2]);
  const EVP_HPKE_KDF *kdf = kdf_of(argv[3]);
  const EVP_HPKE_AEAD *aead = aead_of(argv[4]);
  uint8_t sk[256], enc[256], info[MAX_BUF], aad[MAX_BUF], ct[MAX_BUF],
      exp_ctx[MAX_BUF], pt[MAX_BUF];
  size_t sk_len = hex_decode(argv[5], sk, sizeof(sk));
  size_t enc_len = hex_decode(argv[6], enc, sizeof(enc));
  size_t info_len = hex_decode(argv[7], info, sizeof(info));
  size_t aad_len = hex_decode(argv[8], aad, sizeof(aad));
  size_t ct_len = hex_decode(argv[9], ct, sizeof(ct));
  size_t exp_ctx_len = hex_decode(argv[10], exp_ctx, sizeof(exp_ctx));
  size_t exp_len = (size_t)strtoul(argv[11], NULL, 10);
  EVP_HPKE_KEY *key = key_from_seed(kem, sk, sk_len);
  EVP_HPKE_CTX *ctx = EVP_HPKE_CTX_new();
  if (!EVP_HPKE_CTX_setup_recipient(ctx, key, kdf, aead, enc, enc_len, info,
                                    info_len)) {
    die("setup_recipient failed");
  }
  size_t pt_len = 0;
  if (!EVP_HPKE_CTX_open(ctx, pt, &pt_len, sizeof(pt), ct, ct_len, aad,
                         aad_len)) {
    die("open failed");
  }
  export_and_print(ctx, NULL, 0, pt, pt_len, exp_ctx, exp_ctx_len, exp_len);
  EVP_HPKE_CTX_free(ctx);
  EVP_HPKE_KEY_free(key);
  return 0;
}

static int cmd_auth_seal(int argc, char **argv) {
  /* auth-seal kem kdf aead skS pkR info aad pt expctx explen [seed] */
  if (argc != 12 && argc != 13) die("usage: auth-seal");
  const EVP_HPKE_KEM *kem = kem_of(argv[2]);
  const EVP_HPKE_KDF *kdf = kdf_of(argv[3]);
  const EVP_HPKE_AEAD *aead = aead_of(argv[4]);
  uint8_t sk[256], pk[256], info[MAX_BUF], aad[MAX_BUF], pt[MAX_BUF],
      exp_ctx[MAX_BUF], seed[256], enc[256], ct[MAX_BUF];
  size_t sk_len = hex_decode(argv[5], sk, sizeof(sk));
  size_t pk_len = hex_decode(argv[6], pk, sizeof(pk));
  size_t info_len = hex_decode(argv[7], info, sizeof(info));
  size_t aad_len = hex_decode(argv[8], aad, sizeof(aad));
  size_t pt_len = hex_decode(argv[9], pt, sizeof(pt));
  size_t exp_ctx_len = hex_decode(argv[10], exp_ctx, sizeof(exp_ctx));
  size_t exp_len = (size_t)strtoul(argv[11], NULL, 10);
  size_t seed_len = argc == 13 ? hex_decode(argv[12], seed, sizeof(seed)) : 0;
  EVP_HPKE_KEY *key = key_from_seed(kem, sk, sk_len);
  EVP_HPKE_CTX *ctx = EVP_HPKE_CTX_new();
  size_t enc_len = 0;
  int ok =
      seed_len
          ? EVP_HPKE_CTX_setup_auth_sender_with_seed_for_testing(
                ctx, enc, &enc_len, sizeof(enc), key, kdf, aead, pk, pk_len, info,
                info_len, seed, seed_len)
          : EVP_HPKE_CTX_setup_auth_sender(ctx, enc, &enc_len, sizeof(enc), key,
                                           kdf, aead, pk, pk_len, info, info_len);
  if (!ok) die("setup_auth_sender failed");
  size_t ct_len = 0;
  if (!EVP_HPKE_CTX_seal(ctx, ct, &ct_len, sizeof(ct), pt, pt_len, aad,
                         aad_len)) {
    die("auth seal failed");
  }
  export_and_print(ctx, enc, enc_len, ct, ct_len, exp_ctx, exp_ctx_len, exp_len);
  EVP_HPKE_CTX_free(ctx);
  EVP_HPKE_KEY_free(key);
  return 0;
}

static int cmd_auth_open(int argc, char **argv) {
  /* auth-open kem kdf aead skR pkS enc info aad ct expctx explen */
  if (argc != 13) die("usage: auth-open");
  const EVP_HPKE_KEM *kem = kem_of(argv[2]);
  const EVP_HPKE_KDF *kdf = kdf_of(argv[3]);
  const EVP_HPKE_AEAD *aead = aead_of(argv[4]);
  uint8_t sk[256], pk[256], enc[256], info[MAX_BUF], aad[MAX_BUF], ct[MAX_BUF],
      exp_ctx[MAX_BUF], pt[MAX_BUF];
  size_t sk_len = hex_decode(argv[5], sk, sizeof(sk));
  size_t pk_len = hex_decode(argv[6], pk, sizeof(pk));
  size_t enc_len = hex_decode(argv[7], enc, sizeof(enc));
  size_t info_len = hex_decode(argv[8], info, sizeof(info));
  size_t aad_len = hex_decode(argv[9], aad, sizeof(aad));
  size_t ct_len = hex_decode(argv[10], ct, sizeof(ct));
  size_t exp_ctx_len = hex_decode(argv[11], exp_ctx, sizeof(exp_ctx));
  size_t exp_len = (size_t)strtoul(argv[12], NULL, 10);
  EVP_HPKE_KEY *key = key_from_seed(kem, sk, sk_len);
  EVP_HPKE_CTX *ctx = EVP_HPKE_CTX_new();
  if (!EVP_HPKE_CTX_setup_auth_recipient(ctx, key, kdf, aead, enc, enc_len, info,
                                         info_len, pk, pk_len)) {
    die("setup_auth_recipient failed");
  }
  size_t pt_len = 0;
  if (!EVP_HPKE_CTX_open(ctx, pt, &pt_len, sizeof(pt), ct, ct_len, aad,
                         aad_len)) {
    die("auth open failed");
  }
  export_and_print(ctx, NULL, 0, pt, pt_len, exp_ctx, exp_ctx_len, exp_len);
  EVP_HPKE_CTX_free(ctx);
  EVP_HPKE_KEY_free(key);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) die("usage: hpke_peer <derive|base-seal|base-open|auth-seal|auth-open>");
  if (strcmp(argv[1], "derive") == 0) return cmd_derive(argc, argv);
  if (strcmp(argv[1], "base-seal") == 0) return cmd_base_seal(argc, argv);
  if (strcmp(argv[1], "base-open") == 0) return cmd_base_open(argc, argv);
  if (strcmp(argv[1], "auth-seal") == 0) return cmd_auth_seal(argc, argv);
  if (strcmp(argv[1], "auth-open") == 0) return cmd_auth_open(argc, argv);
  die("unknown command");
  return 1;
}
