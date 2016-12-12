#include <openssl/err.h>
#include <openssl/x509.h>

int main(int argc, char *argv[]) {
  X509_REQ *req;
  int i;
  int nid;

  req = d2i_X509_REQ_fp(stdin, NULL);
  if (req == NULL) {
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  STACK_OF(X509_EXTENSION) *extensions = X509_REQ_get_extensions(req);
  X509_EXTENSION *extn;

  for (i = 0; i < sk_X509_EXTENSION_num(extensions); i++) {
    extn = sk_X509_EXTENSION_value(extensions, i);
    nid = OBJ_obj2nid(extn->object);
    if (nid == NID_subject_alt_name) {
      fwrite(extn->value->data, 1, extn->value->length, stdout);
    }
  }

finish:
  return 0;
}
