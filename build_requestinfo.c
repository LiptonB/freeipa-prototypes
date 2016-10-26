#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


static int
astring_type(const char *attr, const char *p, ssize_t n)
{
	unsigned int i;

	if ((strcasecmp(attr, "CN") != 0) &&
	    (strcasecmp(attr, "commonName") != 0)) {
		return MBSTRING_UTF8;
	}
	if (n < 0) {
		n = strlen(p);
	}
	for (i = 0; i < n; i++) {
		if ((p[i] & 0x80) != 0) {
			return MBSTRING_UTF8;
		}
	}
	return V_ASN1_PRINTABLESTRING;
}

X509_NAME *cm_parse_subject(char *cm_template_subject) {
  char *p, *q, *s;
  int i;
  X509_NAME *subject = NULL;
  if ((subject == NULL) &&
      (cm_template_subject != NULL) &&
      (strlen(cm_template_subject) != 0)) {
    // This isn't really correct, but it will
    //  probably do for now.
    p = cm_template_subject;
    q = p + strcspn(p, ",");
    subject = X509_NAME_new();
    if (subject != NULL) {
      while (*p != '\0') {
        if ((s = memchr(p, '=', q - p)) != NULL) {
          *s = '\0';
          for (i = 0; p[i] != '\0'; i++) {
            p[i] = toupper(p[i]);
          }
          X509_NAME_add_entry_by_txt(subject,
                    p, astring_type(p, s + 1, q - s - 1),
                    (unsigned char *) (s + 1), q - s - 1,
                    -1, 0);
          *s = '=';
        } else {
          X509_NAME_add_entry_by_txt(subject,
                    "CN", astring_type("CN", p, q - p),
                    (unsigned char *) p, q - p,
                    -1, 0);
        }
        p = q + strspn(q, ",");
        q = p + strcspn(p, ",");
      }
    }
  }

  return subject;
}

int
conf_to_req_info(BIO *nconf_bio, BIO *pubkey_bio, unsigned char **out)
{
  int fd;
  CONF *reqdata;
  char *extn_section;
  char *dn_str;
  X509V3_CTX ext_ctx;
  X509_NAME *subject;
  X509_REQ *req;
  unsigned char *buf;
  long errorline = -1;
  int len;
  int i;
  EVP_PKEY *pubkey;

  reqdata = NCONF_new(NULL);
  i = NCONF_load_bio(reqdata, nconf_bio, &errorline);
  if (i <= 0) {
    // TODO: handle error
    // if (errorline <= 0)
    //     BIO_printf(bio_err, "%s: Can't load config file \"%s\"\n",
    //                 opt_getprog(), filename);
    // else
    //     BIO_printf(bio_err, "%s: Error on line %ld of config file \"%s\"\n",
    //                 opt_getprog(), errorline, filename);
    NCONF_free(reqdata);
    return -1;
  }

  dn_str = NCONF_get_string(reqdata, "req", "cm_template_subject");
  subject = cm_parse_subject(dn_str);

  req = X509_REQ_new();
  X509_REQ_set_subject_name(req, subject);
  X509_NAME_free(subject);

  pubkey = d2i_PUBKEY_bio(pubkey_bio, NULL);
  X509_REQ_set_pubkey(req, pubkey);
  EVP_PKEY_free(pubkey);

  X509V3_set_ctx(&ext_ctx, NULL, NULL, req, NULL, 0);
  X509V3_set_nconf(&ext_ctx, reqdata);
  extn_section = NCONF_get_string(reqdata, "req", "req_extensions");
  X509V3_EXT_REQ_add_nconf(reqdata, &ext_ctx, extn_section, req);

  len = i2d_X509_REQ_INFO(req->req_info, NULL);
  buf = OPENSSL_malloc(len);
  if (buf == NULL) {
    return -1;
  }
  *out = buf;
  i2d_X509_REQ_INFO(req->req_info, &buf);

  NCONF_free(reqdata);
  X509_REQ_free(req);

  return len;
}

int main(int argc, char *argv[]) {
  unsigned char *der;
  int len;
  unsigned int i;
  BIO *nconf_bio, *pubkey_bio, *stdout_bio, *base64;

	if (argc != 3) {
    fprintf(stderr, 
        "Usage: %s <SubjectPublicKeyInfo file> <openssl config file>\n", argv[0]);
    exit(1);
  }

  ERR_load_crypto_strings();

  nconf_bio = BIO_new_file(argv[1], "r");

  base64 = BIO_new(BIO_f_base64());
  pubkey_bio = BIO_new_file(argv[2], "r");
  BIO_push(base64, pubkey_bio);

  len = conf_to_req_info(nconf_bio, base64, &der);
  if (len < 0) goto err;

  BIO_pop(base64);
  stdout_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO_push(base64, stdout_bio);

  BIO_write(base64, der, len);
  BIO_flush(base64);

  BIO_free_all(base64);
  BIO_free_all(nconf_bio);
  BIO_free_all(pubkey_bio);
  free(der);

  ERR_free_strings();

  return 0;

err:
  ERR_print_errors_fp(stderr);
  exit(1);
}
