#include <stdio.h>
#include <stdint.h>
#include <openssl/rand.h>

uint32_t random32() {
	uint32_t b;
	int r = RAND_bytes((unsigned char *) &b, 4);
	if (r != 1) {
	  printf("ERROR\n");
	  exit(1);
	}
	return b;
}

int main(int argc, char *argv[]) {
  char *filename = (argc > 1) ? argv[1] : "lwekexlib/lwe_a.h";
  printf("Writing matrix to file %s\n", filename);
  FILE *f = fopen(filename, "wt");
  if (f == NULL) {
    printf("ERROR: Could not open the file");
    return 0;
  }
  int i, j;
  fprintf(f, "uint32_t lwe_a[1024 * 1024] = {\n");
  for (i = 0; i < (1 << 18); i++) {
    fprintf(f, "  ");
    for (j = 0; j < 4; j++) {
      fprintf(f, "0x%08X, ", random32());
    }
    fprintf(f, "\n");
  }
  fprintf(f, "};");
  fclose(f);
  return (0);
}
