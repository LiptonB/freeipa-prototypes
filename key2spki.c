#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "build_requestinfo.h"

EVP_PKEY *read_key(BIO *bio) {
  EVP_PKEY *key; 
  unsigned long err;

  key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (key == NULL) {
    BIO_seek(bio, 0);
    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  }

  if (key == NULL) {
    return NULL;
  }

  return key;
}

int main(int argc, char *argv[]) {
  unsigned char *buf, *out;
  int len;
  BIO *bio;
  EVP_PKEY *pubkey;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <PEM file>\n", argv[0]);
    exit(1);
  }

  bio = BIO_new_file(argv[1], "r");
	if (bio == NULL) goto err;

  pubkey = read_key(bio);
  if (pubkey == NULL) goto err;
  if (1 != BIO_free(bio)) goto err;

  len = i2d_PUBKEY(pubkey, NULL);
  if (len < 0) goto err;

  buf = OPENSSL_malloc(len);
  if (buf == NULL) goto err;

  out = buf;
  len = i2d_PUBKEY(pubkey, &buf);
  if (len < 0) goto err;

  write_to_stdout_b64(out, len);

  OPENSSL_free(out);
  EVP_PKEY_free(pubkey);

  return 0;

err:
  ERR_print_errors_fp(stderr);
  exit(1);
}
