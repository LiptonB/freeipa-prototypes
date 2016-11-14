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
  int fd = -1, status, ret = -1;
  pid_t pid;

  fd = mkstemp(requestdata_file);
  if (fd == -1) {
    perror("ipa_get_requestdata:mkstemp");
    goto finish;
  }
  ipa_command[9] = requestdata_file;

  pid = fork();
  switch (pid) {
    case -1:
      perror("ipa_get_requestdata:fork");
      goto finish;
    case 0:
      // TODO: Why does this need the full path?
      if (execvp("/home/blipton/bin/ipa", ipa_command) == -1) {
        perror("ipa_get_requestdata:execvp");
        goto finish;
      }
      break;
  }
  if (waitpid(pid, &status, 0) == -1) {
    perror("ipa_get_requestdata:waitpid");
    goto finish;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "Error executing ipa command\n");
    goto finish;
  }

  ret = fd;

finish:
  if (ret == -1) {
    if (fd != -1) {
      close(fd);
    }
  }

  return ret;
}

EVP_PKEY *
parse_pkey_from_reqinfo(BIO *reqinfo_bio) {
  int ret;
  unsigned char *buf = NULL, *buf_new = NULL, *buf_remaining;
  size_t buf_size = 2048, tot_size_read = 0;
  int size_read;
  const unsigned char *reqinfo_buf;
  X509_REQ_INFO *req_info = NULL;
  EVP_PKEY *pubkey = NULL;

  while (!BIO_eof(reqinfo_bio)) {
    if (buf_size - tot_size_read < 4096) {
      buf_size *= 2;
      buf_new = realloc(buf, buf_size);
      if (buf_new == NULL) {
        perror("parse_pkey_from_reqinfo:realloc");
        goto finish;
      }
      buf = buf_new;
      buf_remaining = buf + tot_size_read;
    }

    size_read = BIO_read(reqinfo_bio, buf_remaining, buf_size-tot_size_read);
    if (size_read >= 0) {
      tot_size_read += size_read;
      buf_remaining = buf + tot_size_read;
    }
  }
  *buf_remaining = '\0';

  reqinfo_buf = buf;
  req_info = d2i_X509_REQ_INFO(NULL, &reqinfo_buf, size_read);
  if (req_info == NULL){
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  pubkey = X509_PUBKEY_get(req_info->pubkey);
  if (pubkey == NULL){
    ERR_print_errors_fp(stderr);
    goto finish;
  }

finish:
  if (pubkey == NULL) {
    if (buf != NULL) {
      free(buf);
    }
    if (req_info != NULL) {
      X509_REQ_INFO_free(req_info);
    }
    if (pubkey != NULL) {
      EVP_PKEY_free(pubkey);
    }
  }

  return pubkey;
}

int
main(int argc, char *argv[]) {
  // Inputs:
  //   For IPA:
  //   - principal - CERTMONGER_REQ_PRINCIPAL
  //   - cert profile - CERTMONGER_CA_PROFILE
  //   For build_requestinfo:
  //   - DER-encoded CertificationRequestInfo (SubjectPublicKeyInfo comes from here) - stdin

  char *principal = NULL;
  char *profile = NULL;
  EVP_PKEY *pubkey;
  int config_fd;
  FILE *config_file;
  BIO *config_bio = NULL, *reqinfo_bio = NULL, *base64 = NULL;
  unsigned char *encoded;
  int len;
  int retcode = 1;
  
  principal = getenv("CERTMONGER_REQ_PRINCIPAL");
  profile = getenv("CERTMONGER_CA_PROFILE");
  if (principal == NULL) {
    fprintf(stderr, "CERTMONGER_REQ_PRINCIPAL environment variable was not set\n");
    goto finish;
  }
  if (profile == NULL) {
    fprintf(stderr, "CERTMONGER_CA_PROFILE environment variable was not set\n");
    goto finish;
  }

  principal = strdup(principal);
  profile = strdup(profile);
  if (principal == NULL || profile == NULL) {
    perror("main:strdup");
    goto finish;
  }

  reqinfo_bio = BIO_new_fp(stdin, BIO_NOCLOSE);
  base64 = BIO_new(BIO_f_base64());
  if (reqinfo_bio == NULL || base64 == NULL) {
    ERR_print_errors_fp(stderr);
    goto finish;
  }
  BIO_push(base64, reqinfo_bio);

  pubkey = parse_pkey_from_reqinfo(base64);
  if (pubkey == NULL) {
    fprintf(stderr, "Unable to parse public key\n");
    goto finish;
  }
  config_fd = ipa_get_requestdata(principal, profile);
  if (config_fd == -1) {
    fprintf(stderr, "Unable to generate config file\n");
    goto finish;
  }

  config_file = fdopen(config_fd, "r");
  if (config_file == NULL) {
    perror("main:fdopen");
    goto finish;
  }

  config_bio = BIO_new_fp(config_file, BIO_CLOSE);
  if (config_bio == NULL) {
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  len = conf_to_req_info(config_bio, pubkey, &encoded);
  if (len == -1) {
    fprintf(stderr, "Unable to generate CertificationRequestInfo from config\n");
    goto finish;
  }

  write_to_stdout_b64(encoded, len);

  retcode = 0;

finish:
  if (principal != NULL) {
    free(principal);
  }
  if (profile != NULL) {
    free(profile);
  }
  if (config_bio != NULL) {
    BIO_free(config_bio);
  }
  if (base64 != NULL) {
    BIO_free_all(base64);
  }

  return retcode;
}
