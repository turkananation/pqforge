/* OpenSSL OSSL_HPKE peer for DHKEM(X448) and DHKEM(P-521).
   Linked against the pinned libcrypto. Prints hex on stdout. */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 4096

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
  if (strcmp(hex, "-") == 0) return 0;
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

static int mode_of(const char *name) {
  if (strcmp(name, "base") == 0) return OSSL_HPKE_MODE_BASE;
  if (strcmp(name, "psk") == 0) return OSSL_HPKE_MODE_PSK;
  if (strcmp(name, "auth") == 0) return OSSL_HPKE_MODE_AUTH;
  if (strcmp(name, "authpsk") == 0) return OSSL_HPKE_MODE_PSKAUTH;
  die("unknown mode");
  return -1;
}

static uint16_t kem_of(const char *name) {
  if (strcmp(name, "x448") == 0) return OSSL_HPKE_KEM_ID_X448;
  if (strcmp(name, "p521") == 0) return OSSL_HPKE_KEM_ID_P521;
  die("unknown kem");
  return 0;
}

static uint16_t kdf_of(const char *name) {
  if (strcmp(name, "sha256") == 0) return OSSL_HPKE_KDF_ID_HKDF_SHA256;
  if (strcmp(name, "sha384") == 0) return OSSL_HPKE_KDF_ID_HKDF_SHA384;
  if (strcmp(name, "sha512") == 0) return OSSL_HPKE_KDF_ID_HKDF_SHA512;
  die("unknown kdf");
  return 0;
}

static uint16_t aead_of(const char *name) {
  if (strcmp(name, "aes128") == 0) return OSSL_HPKE_AEAD_ID_AES_GCM_128;
  if (strcmp(name, "aes256") == 0) return OSSL_HPKE_AEAD_ID_AES_GCM_256;
  if (strcmp(name, "chacha") == 0) return OSSL_HPKE_AEAD_ID_CHACHA_POLY1305;
  die("unknown aead");
  return 0;
}

static OSSL_HPKE_SUITE suite_of(const char *kem, const char *kdf,
                                const char *aead) {
  OSSL_HPKE_SUITE suite;
  suite.kem_id = kem_of(kem);
  suite.kdf_id = kdf_of(kdf);
  suite.aead_id = aead_of(aead);
  if (OSSL_HPKE_suite_check(suite) != 1) die("suite rejected");
  return suite;
}

static EVP_PKEY *key_from_ikm(OSSL_HPKE_SUITE suite, const uint8_t *ikm,
                              size_t ikm_len, uint8_t *pub, size_t *pub_len) {
  EVP_PKEY *key = NULL;
  if (OSSL_HPKE_keygen(suite, pub, pub_len, &key, ikm, ikm_len, NULL, NULL) !=
      1) {
    die("OSSL_HPKE_keygen failed");
  }
  return key;
}

static void apply_psk(OSSL_HPKE_CTX *ctx, const uint8_t *psk, size_t psk_len,
                      const uint8_t *psk_id, size_t psk_id_len) {
  if (psk_len == 0 && psk_id_len == 0) return;
  if (psk_id_len >= MAX_BUF) die("psk id too long");
  char id[MAX_BUF];
  memcpy(id, psk_id, psk_id_len);
  id[psk_id_len] = 0;
  if (strlen(id) != psk_id_len) die("psk id contains a NUL");
  if (OSSL_HPKE_CTX_set1_psk(ctx, id, psk, psk_len) != 1) die("set psk failed");
}

static int cmd_derive(int argc, char **argv) {
  if (argc != 5) die("usage: derive kem kdf ikm_hex");
  OSSL_HPKE_SUITE suite = suite_of(argv[2], argv[3], "aes128");
  uint8_t ikm[MAX_BUF], pub[MAX_BUF];
  size_t ikm_len = hex_decode(argv[4], ikm, sizeof(ikm));
  size_t pub_len = sizeof(pub);
  EVP_PKEY *key = key_from_ikm(suite, ikm, ikm_len, pub, &pub_len);
  hex_print(pub, pub_len);
  printf("\n");
  EVP_PKEY_free(key);
  return 0;
}

static int cmd_seal(int argc, char **argv) {
  /* seal mode kem kdf aead pkR info aad pt exp explen ikmE psk pskid ikmS */
  if (argc != 16) die("usage: seal");
  int mode = mode_of(argv[2]);
  OSSL_HPKE_SUITE suite = suite_of(argv[3], argv[4], argv[5]);
  uint8_t pk_r[MAX_BUF], info[MAX_BUF], aad[MAX_BUF], pt[MAX_BUF], exp[MAX_BUF];
  uint8_t ikm_e[MAX_BUF], psk[MAX_BUF], psk_id[MAX_BUF], ikm_s[MAX_BUF];
  uint8_t enc[MAX_BUF], ct[MAX_BUF], exported[MAX_BUF], sender_pub[MAX_BUF];
  size_t pk_r_len = hex_decode(argv[6], pk_r, sizeof(pk_r));
  size_t info_len = hex_decode(argv[7], info, sizeof(info));
  size_t aad_len = hex_decode(argv[8], aad, sizeof(aad));
  size_t pt_len = hex_decode(argv[9], pt, sizeof(pt));
  size_t exp_len_in = hex_decode(argv[10], exp, sizeof(exp));
  size_t export_len = (size_t)strtoul(argv[11], NULL, 10);
  size_t ikm_e_len = hex_decode(argv[12], ikm_e, sizeof(ikm_e));
  size_t psk_len = hex_decode(argv[13], psk, sizeof(psk));
  size_t psk_id_len = hex_decode(argv[14], psk_id, sizeof(psk_id));
  size_t ikm_s_len = hex_decode(argv[15], ikm_s, sizeof(ikm_s));
  (void)exp_len_in;
  if (export_len > sizeof(exported)) die("export too long");

  OSSL_HPKE_CTX *ctx =
      OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
  if (ctx == NULL) die("sender ctx");
  if (OSSL_HPKE_CTX_set1_ikme(ctx, ikm_e, ikm_e_len) != 1) die("set ikme");
  apply_psk(ctx, psk, psk_len, psk_id, psk_id_len);
  EVP_PKEY *sender = NULL;
  if (ikm_s_len != 0) {
    size_t sender_pub_len = sizeof(sender_pub);
    sender = key_from_ikm(suite, ikm_s, ikm_s_len, sender_pub, &sender_pub_len);
    if (OSSL_HPKE_CTX_set1_authpriv(ctx, sender) != 1) die("set authpriv");
  }
  size_t enc_len = sizeof(enc);
  if (OSSL_HPKE_encap(ctx, enc, &enc_len, pk_r, pk_r_len, info, info_len) != 1) {
    die("encap failed");
  }
  size_t ct_len = sizeof(ct);
  if (OSSL_HPKE_seal(ctx, ct, &ct_len, aad, aad_len, pt, pt_len) != 1) {
    die("seal failed");
  }
  if (OSSL_HPKE_export(ctx, exported, export_len, exp, exp_len_in) != 1) {
    die("export failed");
  }
  hex_print(enc, enc_len);
  printf(" ");
  hex_print(ct, ct_len);
  printf(" ");
  hex_print(exported, export_len);
  printf("\n");
  EVP_PKEY_free(sender);
  OSSL_HPKE_CTX_free(ctx);
  return 0;
}

static int cmd_open(int argc, char **argv) {
  /* open mode kem kdf aead ikmR enc info aad ct exp explen psk pskid pkS */
  if (argc != 16) die("usage: open");
  int mode = mode_of(argv[2]);
  OSSL_HPKE_SUITE suite = suite_of(argv[3], argv[4], argv[5]);
  uint8_t ikm_r[MAX_BUF], enc[MAX_BUF], info[MAX_BUF], aad[MAX_BUF], ct[MAX_BUF];
  uint8_t exp[MAX_BUF], psk[MAX_BUF], psk_id[MAX_BUF], pk_s[MAX_BUF];
  uint8_t pub[MAX_BUF], pt[MAX_BUF], exported[MAX_BUF];
  size_t ikm_r_len = hex_decode(argv[6], ikm_r, sizeof(ikm_r));
  size_t enc_len = hex_decode(argv[7], enc, sizeof(enc));
  size_t info_len = hex_decode(argv[8], info, sizeof(info));
  size_t aad_len = hex_decode(argv[9], aad, sizeof(aad));
  size_t ct_len = hex_decode(argv[10], ct, sizeof(ct));
  size_t exp_len_in = hex_decode(argv[11], exp, sizeof(exp));
  size_t export_len = (size_t)strtoul(argv[12], NULL, 10);
  size_t psk_len = hex_decode(argv[13], psk, sizeof(psk));
  size_t psk_id_len = hex_decode(argv[14], psk_id, sizeof(psk_id));
  size_t pk_s_len = hex_decode(argv[15], pk_s, sizeof(pk_s));
  if (export_len > sizeof(exported)) die("export too long");

  size_t pub_len = sizeof(pub);
  EVP_PKEY *recipient = key_from_ikm(suite, ikm_r, ikm_r_len, pub, &pub_len);
  OSSL_HPKE_CTX *ctx =
      OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
  if (ctx == NULL) die("receiver ctx");
  apply_psk(ctx, psk, psk_len, psk_id, psk_id_len);
  if (pk_s_len != 0 &&
      OSSL_HPKE_CTX_set1_authpub(ctx, pk_s, pk_s_len) != 1) {
    die("set authpub");
  }
  if (OSSL_HPKE_decap(ctx, enc, enc_len, recipient, info, info_len) != 1) {
    die("decap failed");
  }
  size_t pt_len = sizeof(pt);
  if (OSSL_HPKE_open(ctx, pt, &pt_len, aad, aad_len, ct, ct_len) != 1) {
    die("open failed");
  }
  if (OSSL_HPKE_export(ctx, exported, export_len, exp, exp_len_in) != 1) {
    die("export failed");
  }
  hex_print(pt, pt_len);
  printf(" ");
  hex_print(exported, export_len);
  printf("\n");
  EVP_PKEY_free(recipient);
  OSSL_HPKE_CTX_free(ctx);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) die("usage: derive|seal|open");
  if (strcmp(argv[1], "derive") == 0) return cmd_derive(argc, argv);
  if (strcmp(argv[1], "seal") == 0) return cmd_seal(argc, argv);
  if (strcmp(argv[1], "open") == 0) return cmd_open(argc, argv);
  die("unknown command");
  return 1;
}
