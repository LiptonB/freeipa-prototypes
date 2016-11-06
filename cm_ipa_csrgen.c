#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openssl/bio.h>
#include <openssl/err.h>

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
      if (execvp("ipa", ipa_command) == -1) {
        //TODO: handle error
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

EVP_PKEY *
parse_pkey_from_reqinfo(FILE *reqinfo_file) {
  // TODO: implement

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
  BIO *config_bio;
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

  pubkey = parse_pkey_from_reqinfo(stdin);
  config_fd = ipa_get_requestdata(principal, profile);

  //bio = BIO_new_fd(fd, BIO_CLOSE);
  config_bio = BIO_new_fp(fdopen(config_fd, "r"), BIO_CLOSE);
  if (config_bio == NULL) goto err;

  len = conf_to_req_info(config_bio, pubkey, &encoded);

  free(principal);
  free(profile);
  BIO_free(config_bio);

err:
  ERR_print_errors_fp(stderr);
  exit(1);
}
