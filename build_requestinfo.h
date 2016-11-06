#include <openssl/bio.h>
#include <openssl/evp.h>

int conf_to_req_info(BIO *nconf_bio, EVP_PKEY *pubkey, unsigned char **out);
int write_to_stdout_b64(unsigned char *data, int len);
