/* Verify one leaf PEM against one CA PEM with the pinned BoringSSL.
   BoringSSL's bssl tool has no x509 or verify command, so CI links this
   against the pinned libcrypto. Exit 0 only when X509_verify_cert succeeds. */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>

static X509 *read_pem(const char *path) {
  BIO *bio = BIO_new_file(path, "r");
  if (bio == NULL) return NULL;
  X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return cert;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: boringssl_verify leaf.pem ca.pem\n");
    return 2;
  }
  X509 *leaf = read_pem(argv[1]);
  X509 *ca = read_pem(argv[2]);
  if (leaf == NULL || ca == NULL) {
    fprintf(stderr, "could not read a certificate\n");
    return 1;
  }
  X509_STORE *store = X509_STORE_new();
  X509_STORE_add_cert(store, ca);
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  if (X509_STORE_CTX_init(ctx, store, leaf, NULL) != 1) {
    fprintf(stderr, "X509_STORE_CTX_init failed\n");
    return 1;
  }
  X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER);
  if (X509_verify_cert(ctx) != 1) {
    int error = X509_STORE_CTX_get_error(ctx);
    fprintf(stderr, "%s\n", X509_verify_cert_error_string(error));
    ERR_print_errors_fp(stderr);
    return 1;
  }
  return 0;
}
