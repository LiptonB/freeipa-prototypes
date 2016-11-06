#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "build_requestinfo.h"

int main(int argc, char *argv[]) {
  unsigned char *buf, *out;
  int len;
  BIO *bio;
  X509_REQ *req;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <PEM file>\n", argv[0]);
    exit(1);
  }

  bio = BIO_new_file(argv[1], "r");
	if (bio == NULL) goto err;

  req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
  if (req == NULL) goto err;
  if (1 != BIO_free(bio)) goto err;

  len = i2d_X509_REQ_INFO(req->req_info, NULL);
  if (len < 0) goto err;

  buf = OPENSSL_malloc(len);
  if (buf == NULL) goto err;

  out = buf;
  len = i2d_X509_REQ_INFO(req->req_info, &buf);
  if (len < 0) goto err;

  write_to_stdout_b64(out, len);

  OPENSSL_free(out);
  X509_REQ_free(req);

  return 0;

err:
  ERR_print_errors_fp(stderr);
  exit(1);
}
