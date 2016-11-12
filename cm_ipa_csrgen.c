#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "build_requestinfo.h"

int
ipa_get_requestdata(char *principal, char *profile)
{
  char *ipa_command[] = {"ipa", "cert-get-requestdata", "--principal", principal,
    "--profile-id", profile, "--helper", "certmonger", "--out", NULL, NULL};
  char requestdata_file[] = "/tmp/cm.XXXXXX";
  int fd, status;
  pid_t pid;

  // TODO: make sure principal and profile aren't NULL
  fd = mkstemp(requestdata_file);
  ipa_command[9] = requestdata_file;

  pid = fork();
  switch (pid) {
    case -1:
      //TODO: handle error
      return -1;
    case 0:
      if (execvp("/home/blipton/bin/ipa", ipa_command) == -1) {
        //TODO: handle error
        perror("execvp");
        return -1;
      }
      break;
  }
  if (waitpid(pid, &status, 0) == -1) {
    //TODO: handle error
    return -1;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    // TODO: handle error
    return -1;
  }
  return fd;
}

// TODO: fix memory management and error handling
EVP_PKEY *
parse_pkey_from_reqinfo(BIO *reqinfo_bio) {
  int ret;
  unsigned char *buf = NULL, *buf_remaining;
  size_t buf_size = 2048, tot_size_read = 0, size_read;
  const unsigned char *reqinfo_buf;
  X509_REQ_INFO *req_info;
  EVP_PKEY *pubkey;

  while (!BIO_eof(reqinfo_bio)) {
    if (buf_size - tot_size_read < 4096) {
      buf_size *= 2;
      buf = realloc(buf, buf_size);
      buf_remaining = buf + tot_size_read;
      if (buf == NULL) goto err;
    }

    size_read = BIO_read(reqinfo_bio, buf_remaining, buf_size-tot_size_read);
    tot_size_read += size_read;
    buf_remaining = buf + tot_size_read;
  }
  *buf_remaining = '\0';

  reqinfo_buf = buf;
  req_info = d2i_X509_REQ_INFO(NULL, &reqinfo_buf, size_read);
  if (req_info == NULL) goto err;

  pubkey = X509_PUBKEY_get(req_info->pubkey);
  if (pubkey != NULL) {
    return pubkey;
  }

err:
  return NULL;
}

int main(int argc, char *argv[]) {
  // Inputs:
  //   For IPA:
  //   - principal - CERTMONGER_REQ_PRINCIPAL
  //   - cert profile - CERTMONGER_CA_PROFILE
  //   For build_requestinfo:
  //   - DER-encoded CertificationRequestInfo (SubjectPublicKeyInfo comes from here) - stdin

  char *principal = getenv("CERTMONGER_REQ_PRINCIPAL");
  char *profile = getenv("CERTMONGER_CA_PROFILE");
  EVP_PKEY *pubkey;
  int config_fd;
  FILE *config_file;
  BIO *config_bio, *reqinfo_bio, *base64;
  unsigned char *encoded;
  int len;
  
  if (principal == NULL) {
    // TODO: raise
  }
  if (profile == NULL) {
    // TODO: raise
  }

  principal = strdup(principal);
  profile = strdup(profile);

  reqinfo_bio = BIO_new_fp(stdin, BIO_NOCLOSE);
  base64 = BIO_new(BIO_f_base64());
  BIO_push(base64, reqinfo_bio);

  pubkey = parse_pkey_from_reqinfo(base64);
  config_fd = ipa_get_requestdata(principal, profile);

  //bio = BIO_new_fd(fd, BIO_CLOSE);
  config_file = fdopen(config_fd, "r");
  config_bio = BIO_new_fp(config_file, BIO_CLOSE);
  if (config_bio == NULL) goto err;

  len = conf_to_req_info(config_bio, pubkey, &encoded);

  write_to_stdout_b64(encoded, len);

  free(principal);
  free(profile);
  BIO_free(config_bio);
  BIO_free_all(base64);

  return 0;

err:
  ERR_print_errors_fp(stderr);
  exit(1);
}
