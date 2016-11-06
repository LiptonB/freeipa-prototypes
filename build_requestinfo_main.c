#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "build_requestinfo.h"

int
main(int argc, char *argv[]) {
  unsigned char *der;
  int len;
  unsigned int i;
  BIO *nconf_bio = NULL, *pubkey_bio = NULL, *stdout_bio = NULL, *base64 = NULL;
  EVP_PKEY *pubkey;

	if (argc != 3) {
    fprintf(stderr,
        "Usage: %s <SubjectPublicKeyInfo file> <openssl config file>\n",
        argv[0]);
    exit(1);
  }

  ERR_load_crypto_strings();

  nconf_bio = BIO_new_file(argv[1], "r");
  if (nconf_bio == NULL) goto err;

  base64 = BIO_new(BIO_f_base64());
  if (base64 == NULL) goto err;
  pubkey_bio = BIO_new_file(argv[2], "r");
  if (pubkey_bio == NULL) goto err;
  BIO_push(base64, pubkey_bio);

  pubkey = d2i_PUBKEY_bio(base64, NULL);

  len = conf_to_req_info(nconf_bio, pubkey, &der);
  if (len < 0) goto err;

  if (!write_to_stdout_b64(der, len)) goto err;

  EVP_PKEY_free(pubkey);
  BIO_free_all(base64);
  BIO_free_all(nconf_bio);
  free(der);

  ERR_free_strings();

  return 0;

err:
  ERR_print_errors_fp(stderr);
  exit(1);
}
