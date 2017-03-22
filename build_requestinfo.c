#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/err.h>
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

/* Adapted from openssl:apps/req.c
 */
int
parse_dn_section(X509_NAME *subj, STACK_OF(CONF_VALUE) *dn_sk) {
  int i;
  char *p, *q;
  char *type;
  CONF_VALUE *v;

	for (i = 0; i < sk_CONF_VALUE_num(dn_sk); i++) {
    int mval;
    v = sk_CONF_VALUE_value(dn_sk, i);
    p = q = NULL;
    type = v->name;
    /*
     * Skip past any leading X. X: X, etc to allow for multiple instances
     */
    for (p = v->name; *p; p++)
      if ((*p == ':') || (*p == ',') || (*p == '.')) {
        p++;
        if (*p)
          type = p;
        break;
      }
    if (*p == '+')
    {
      p++;
      mval = -1;
    } else
      mval = 0;
    if (!X509_NAME_add_entry_by_txt(subj, type, MBSTRING_UTF8,
                    (unsigned char *)v->value, -1, -1,
                    mval))
      return 0;
  }

  if (!X509_NAME_entry_count(subj)) {
    fprintf(stderr, "error, subject in config file is empty\n");
    return 0;
  }

  return 1;
}

int
conf_to_req_info(BIO *nconf_bio, EVP_PKEY *pubkey, unsigned char **out)
{
  int fd;
  CONF *reqdata;
  char *extn_section;
  char *dn_sect = NULL;
  X509V3_CTX ext_ctx;
  X509_NAME *subject = NULL;
  X509_REQ *req = NULL;
  STACK_OF(CONF_VALUE) *dn_sk;
  unsigned char *buf;
  long errorline = -1;
  int len = -1;
  int i;

  *out = NULL;

  reqdata = NCONF_new(NULL);
  i = NCONF_load_bio(reqdata, nconf_bio, &errorline);
  if (i <= 0) {
    if (errorline <= 0) {
      fprintf(stderr, "Can't load config file\n");
    } else {
      fprintf(stderr, "Error on line %ld of config file\n", errorline);
    }
    goto finish;
  }

  dn_sect = NCONF_get_string(reqdata, "req", "distinguished_name");
  if (dn_sect == NULL) {
    ERR_print_errors_fp(stderr);
    goto finish;
  }
  dn_sk = NCONF_get_section(reqdata, dn_sect);
  if (dn_sk == NULL) {
    fprintf(stderr, "Config file is missing \"distinguished_name\"\n");
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  req = X509_REQ_new();
  if (req == NULL) {
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  subject = X509_REQ_get_subject_name(req);

  if (!parse_dn_section(subject, dn_sk)) {
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  if (!X509_REQ_set_pubkey(req, pubkey)) {
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  X509V3_set_ctx(&ext_ctx, NULL, NULL, req, NULL, 0);
  X509V3_set_nconf(&ext_ctx, reqdata);
  extn_section = NCONF_get_string(reqdata, "req", "req_extensions");
  if (extn_section == NULL) {
    // TODO: Could it just be missing from config?
  }
  if (!X509V3_EXT_REQ_add_nconf(reqdata, &ext_ctx, extn_section, req)) {
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  len = i2d_X509_REQ_INFO(req->req_info, NULL);
  if (len < 0) {
    len = -1;
    ERR_print_errors_fp(stderr);
    goto finish;
  }
  buf = OPENSSL_malloc(len);
  if (buf == NULL) {
    perror("conf_to_req_info:malloc");
    goto finish;
  }
  *out = buf;
  len = i2d_X509_REQ_INFO(req->req_info, &buf);
  if (len < 0) {
    len = -1;
    ERR_print_errors_fp(stderr);
    goto finish;
  }

finish:
  if (reqdata != NULL) {
    NCONF_free(reqdata);
  }
  if (req != NULL) {
    X509_REQ_free(req);
  }
  if (len == -1) {
    if (*out != NULL) {
      OPENSSL_free(*out);
      *out = NULL;
    }
  }

  return len;
}

int
write_to_stdout_b64(unsigned char *data, int len) {
  BIO *stdout_bio = NULL, *base64 = NULL;

  stdout_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  if (stdout_bio == NULL) goto err;
  base64 = BIO_new(BIO_f_base64());
  if (base64 == NULL) goto err;
  BIO_push(base64, stdout_bio);

  if (len != BIO_write(base64, data, len)) goto err;
  if (1 != BIO_flush(base64)) goto err;

  BIO_free_all(base64);

  return 0;

err:
  return -1;
}
