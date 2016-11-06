#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openssl/bio.h>

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

/*
void
cm_update_with_ipa_requestdata(struct cm_store_entry *entry)
{
  int fd;
  BIO *bio;
  CONF *reqdata;
  FILE *conffile;
  //STACK_OF(CONF_VALUE) *req_vals;
  //CONF_VALUE *val;
  char *extn_section;
  long errorline = -1;
  int i;
  X509_REQ *req = NULL;
  X509_ATTRIBUTE *extn_attr;
  X509V3_CTX ctx;

  fd = cm_ipa_get_requestdata(entry);
  conffile = fdopen(fd, "r");
  //bio = BIO_new_fd(fd, BIO_CLOSE);
  bio = BIO_new_fp(conffile, BIO_CLOSE);

  reqdata = NCONF_new(NULL);
  i = NCONF_load_bio(reqdata, bio, &errorline);
  if (i <= 0) {
    // TODO: handle error
    // if (errorline <= 0)
    //     BIO_printf(bio_err, "%s: Can't load config file \"%s\"\n",
    //                 opt_getprog(), filename);
    // else
    //     BIO_printf(bio_err, "%s: Error on line %ld of config file \"%s\"\n",
    //                 opt_getprog(), errorline, filename);
    NCONF_free(reqdata);
    return;
  }

  BIO_free(bio);

  entry->cm_template_subject = NCONF_get_string(reqdata, "req",
      "cm_template_subject");
  extn_section = NCONF_get_string(reqdata, "req", "req_extensions");

  req = X509_REQ_new();
  X509V3_set_ctx(&ctx, NULL, NULL, req, NULL, 0);
  X509V3_set_nconf(&ctx, reqdata);
  if (!X509V3_EXT_REQ_add_nconf(reqdata, &ctx, extn_section, req)) {
    // TODO: handle error
    // BIO_printf(bio_err,
    //             "Error Loading request extension section %s\n",
    //             req_exts);
    // goto end;
  }

  extn_attr = X509_REQ_get_attr(req, 0);
  
  // entry->cm_template_extensions_der =
}
*/

EVP_PKEY *
parse_pkey_from_reqinfo(FILE *reqinfo_file) {

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

  len = conf_to_req_info(config_bio, pubkey, &encoded);

  free(principal);
  free(profile);
  BIO_free(config_bio);
}
