#include <stdio.h>

#include "asn1/SubjectAltName.h"

int main(int argc, char *argv[]) {
	FILE *xerfile;
  unsigned char *buf = NULL, *buf_new = NULL, *buf_remaining;
  size_t buf_size = 2048, tot_size_read = 0;
  int size_read;
	asn_dec_rval_t rval;
	SubjectAltName_t subjectAltName;


	if (argc != 2) {
		fprintf(stderr, "Usage: %s <XERfile>\n", argv[0]);
		exit(1);
	}

	xerfile = fopen(argv[1], "r");

  while (!feof(xerfile)) {
    if (buf_size - tot_size_read < 4096) {
      buf_size *= 2;
      buf_new = realloc(buf, buf_size);
      if (buf_new == NULL) {
        perror("xer2der:realloc");
        goto finish;
      }
      buf = buf_new;
      buf_remaining = buf + tot_size_read;
    }

    size_read = fread(buf_remaining, 1, buf_size-tot_size_read, xerfile);
    if (size_read >= 0) {
      tot_size_read += size_read;
      buf_remaining = buf + tot_size_read;
    }
  }
  *buf_remaining = '\0';
	fclose(xerfile);

	rval = xer_decode(NULL, &asn_DEF_SubjectAltName, (void **)&subjectAltName, buf, buf_size);


	return 0;
finish:
	exit(2);
}
