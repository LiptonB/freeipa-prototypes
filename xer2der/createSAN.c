#include <unistd.h>

#include "SubjectAltName.h"

void print_xer(SubjectAltName_t *san) {
  int rval;

  rval = xer_fprint(stdout, &asn_DEF_SubjectAltName, san);
}

void print_der(SubjectAltName_t *san) {
  char buffer[1024];
  asn_enc_rval_t rval;

  rval = der_encode_to_buffer(&asn_DEF_SubjectAltName, san, buffer, sizeof(buffer));

  if (rval.encoded == -1) {
    fprintf(stderr, "Error encoding\n");
  } else {
    fwrite(buffer, 1, rval.encoded, stdout);
  }
}

int main(int argc, char *argv[]) {
  SubjectAltName_t san = { 0 };
  GeneralName_t *generalName = calloc(1, sizeof(GeneralName_t));
  char *email = "blipton@redhat.com";

  generalName->present = GeneralName_PR_rfc822Name;
  OCTET_STRING_fromString(&generalName->choice.rfc822Name, email);
  ASN_SEQUENCE_ADD(&san, generalName);

  print_der(&san);
}
