#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

X509_PUBKEY *read_key(BIO *bio) {
  EVP_PKEY *key; 
  X509_PUBKEY *x509_pubkey = NULL;
  unsigned long err;

  key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (key == NULL) {
    BIO_seek(bio, 0);
    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  }

  if (key == NULL) {
    return NULL;
  }

  X509_PUBKEY_set(&x509_pubkey, key);

  EVP_PKEY_free(key);

  return x509_pubkey;
}

void write_base64(unsigned char *buf, int len) {
  BIO *bio, *b64;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO_push(b64, bio);
  BIO_write(b64, buf, len);
  BIO_flush(b64);
  
  BIO_free_all(b64);
}

int main(int argc, char *argv[]) {
  unsigned char *buf, *out;
  int len;
  BIO *bio;
  X509_PUBKEY *pubkey;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <PEM file>\n", argv[0]);
    exit(1);
  }

  bio = BIO_new_file(argv[1], "r");
	if (bio == NULL) goto err;

  pubkey = read_key(bio);
  if (pubkey == NULL) goto err;
  if (1 != BIO_free(bio)) goto err;

  len = i2d_X509_PUBKEY(pubkey, NULL);
  if (len < 0) goto err;

  buf = OPENSSL_malloc(len);
  if (buf == NULL) goto err;

  out = buf;
  len = i2d_X509_PUBKEY(pubkey, &buf);
  if (len < 0) goto err;

  write_base64(out, len);

  OPENSSL_free(out);
  X509_PUBKEY_free(pubkey);

  return 0;

err:
  ERR_print_errors_fp(stderr);
  exit(1);
}
