#!/usr/bin/python

import base64
import sys

from cffi import FFI
import ctypes.util

_ffi = FFI()

_ffi.cdef('''
typedef ... CONF;
typedef ... CONF_METHOD;
typedef ... BIO;
typedef ... ipa_STACK_OF_CONF_VALUE;

/* openssl/conf.h */
CONF *NCONF_new(CONF_METHOD *meth);
void NCONF_free(CONF *conf);
int NCONF_load_bio(CONF *conf, BIO *bp, long *eline);
ipa_STACK_OF_CONF_VALUE *NCONF_get_section(const CONF *conf,
                                        const char *section);
char *NCONF_get_string(const CONF *conf, const char *group, const char *name);

/* openssl/bio.h */
BIO *BIO_new_mem_buf(const void *buf, int len);
int BIO_free(BIO *a);

/* openssl/asn1.h */
typedef struct ASN1_ENCODING_st {
    unsigned char *enc;         /* DER encoding */
    long len;                   /* Length of encoding */
    int modified;               /* set to 1 if 'enc' is invalid */
} ASN1_ENCODING;

/* openssl/evp.h */
typedef ... EVP_PKEY;

void EVP_PKEY_free(EVP_PKEY *pkey);

/* openssl/x509.h */
typedef ... ASN1_INTEGER;
typedef ... ASN1_BIT_STRING;
typedef ... X509_ALGOR;
typedef ... X509_NAME;
typedef ... X509_PUBKEY;
typedef ... ipa_STACK_OF_X509_ATTRIBUTE;

typedef struct X509_req_info_st {
    ASN1_ENCODING enc;
    ASN1_INTEGER *version;
    X509_NAME *subject;
    X509_PUBKEY *pubkey;
    /*  d=2 hl=2 l=  0 cons: cont: 00 */
    ipa_STACK_OF_X509_ATTRIBUTE *attributes; /* [ 0 ] */
} X509_REQ_INFO;

typedef struct X509_req_st {
    X509_REQ_INFO *req_info;
    X509_ALGOR *sig_alg;
    ASN1_BIT_STRING *signature;
    int references;
} X509_REQ;

X509_REQ *X509_REQ_new(void);
void X509_REQ_free(X509_REQ *);
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);
int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
''')

_libcrypto = _ffi.dlopen(ctypes.util.find_library('crypto'))

NULL = _ffi.NULL

# openssl/conf.h
NCONF_new = _libcrypto.NCONF_new
NCONF_free = _libcrypto.NCONF_free
NCONF_load_bio = _libcrypto.NCONF_load_bio
NCONF_get_section = _libcrypto.NCONF_get_section
NCONF_get_string = _libcrypto.NCONF_get_string

# openssl/bio.h
BIO_new_mem_buf = _libcrypto.BIO_new_mem_buf
BIO_free = _libcrypto.BIO_free

# openssl/x509.h
X509_REQ_new = _libcrypto.X509_REQ_new
X509_REQ_free = _libcrypto.X509_REQ_free
X509_REQ_set_pubkey = _libcrypto.X509_REQ_set_pubkey
def X509_REQ_get_subject_name(req):
    return req.req_info.subject
d2i_PUBKEY_bio = _libcrypto.d2i_PUBKEY_bio

# openssl/evp.h
EVP_PKEY_free = _libcrypto.EVP_PKEY_free

class OpenSSLException(Exception):
    pass

def openssl_raise():
    msgs = []

    code = ERR_get_error()
    while code != 0:
        msg = ERR_error_string(code, NULL)
        msgs.append(_ffi.string(msg))
        code = ERR_get_error()

    raise OpenSSLException('\n'.join(msgs))


def parse_dn_section(subject, dn_sk):
    pass



def build_requestinfo(config, public_key_info):
    reqdata = NULL
    req = NULL
    nconf_bio = NULL
    pubkey_bio = NULL
    pubkey = NULL

    try:
        reqdata = NCONF_new(NULL)
        if reqdata == NULL:
            openssl_raise()

        nconf_bio = BIO_new_mem_buf(config, len(config))
        errorline = _ffi.new('long[1]', [-1])
        i = NCONF_load_bio(reqdata, nconf_bio, errorline);
        if i < 0:
            if errorline[0] < 0:
                raise OpenSSLException("Can't load config file")
            else:
                raise OpenSSLException('Error on line %d of config file' % errorline[0])

        dn_sect = NCONF_get_string(reqdata, 'req', 'distinguished_name')
        if dn_sect == NULL:
            raise OpenSSLException('Unable to find "distinguished_name" key in config')

        dn_sk = NCONF_get_section(reqdata, dn_sect);
        if dn_sk == NULL:
            raise OpenSSLException(
                'Unable to find "%s" section in config' % _ffi.string(dn_sect))

        pubkey_bio = BIO_new_mem_buf(public_key_info, len(public_key_info))
        pubkey = d2i_PUBKEY_bio(pubkey_bio, NULL)
        if pubkey == NULL:
            openssl_raise()

        req = X509_REQ_new();
        if req == NULL:
            openssl_raise()

        subject = X509_REQ_get_subject_name(req);

        parse_dn_section(subject, dn_sk)

        if not X509_REQ_set_pubkey(req, pubkey):
            openssl_raise()

    finally:
        if reqdata != NULL:
            NCONF_free(reqdata)
        if req != NULL:
            X509_REQ_free(req)
        if nconf_bio != NULL:
            BIO_free(nconf_bio)
        if pubkey_bio != NULL:
            BIO_free(pubkey_bio)
        if pubkey != NULL:
            EVP_PKEY_free(pubkey)

        #if (len == -1) {
        #    if (*out != NULL) {
        #        OPENSSL_free(*out);
        #        *out = NULL;
        #    }
        #}

if __name__ == '__main__':
    config = '''
[ req ]
prompt = no
encrypt_key = no

distinguished_name = dn
req_extensions = exts

[ dn ]
commonName = "user"

[ exts ]
subjectAltName=email:user@example.test
keyUsage=digitalSignature,nonRepudiation
subjectAltName=IP:192.168.1.1,URI:http://test.example.com,email:user@example.test
extendedKeyUsage=clientAuth,emailProtection
'''

    public_key_info = base64.b64decode('''
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA069mZkJrL23wxAfWY5n4
hW1k5GLLGVXA2k1io7JWNPbe2Gcrnxezb+7ENesyf69VFCNJ9c7S9CF7lXN7LLOz
dlWWTbqf550WLhBUxHr+Euj5kfsdQkQx+W1uwV3zc/hqft2iJ0L8sqP0QJ/MIX4Q
Q6yuTD70lfPGKuQNPYAzay3G7CHrEInqNekVFEkHtJtLEPdkeUv4kfIAiD6BSM9+
OQxtApp6pkR7chpV1EAZc+qUTGlKC61HRFQJ955fYAlHomGbCCzz+qzY67zYlHCt
0iPga+nGMMx+lrkrlNEQDOV7sHgNDiJvi5UmV9mXRJ6vz8yiJ/SDkNdqzOj70wjM
gQIDAQAB
''')

    build_requestinfo(config, public_key_info)
