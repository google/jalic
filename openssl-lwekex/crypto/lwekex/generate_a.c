/*
Copyright 2015 Google Inc. All Rights Reserved.

Author: nikolaenko@google.com (Valeria Nikolaenko)
Author: pseudorandom@google.com (Ananth Raghunathan)
Author: mironov@google.com (Ilya Mironov)
*/

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
  char *filename = (argc > 1) ? argv[1] : "lwe_a.h";
  printf("Writing matrix to file %s\n", filename);
  FILE *f = fopen(filename, "wt");
  if (f == NULL) {
    printf("ERROR: Could not open the file");
    return 0;
  }
  int i, j, index = 0;
  uint32_t lwe_a_transpose[1024 * 1024];
  uint32_t tmp;
  fprintf(f, "/*\nCopyright 2015 Google Inc. All Rights Reserved.\n\nAuthor: nikolaenko@google.com (Valeria Nikolaenko)\nAuthor: pseudorandom@google.com (Ananth Raghunathan)\nAuthor: mironov@google.com (Ilya Mironov)\n*/\n");
  fprintf(f, "#ifndef _LWE_A_H_\n#define _LWE_A_H_\n\n");
  fprintf(f, "uint32_t lwe_a[1024 * 1024] = {\n");
  for (i = 0; i < (1 << 18); i++) {
    fprintf(f, "  ");
    for (j = 0; j < 4; j++) {
      tmp = random32();
      index = i * 4 + j;
      lwe_a_transpose[(index % 1024) * 1024 + index / 1024] = tmp;
      fprintf(f, "0x%08X, ", tmp);
    }
    fprintf(f, "\n");
  }
  fprintf(f, "};\n\n");

  fprintf(f, "uint32_t lwe_a_transpose[1024 * 1024] = {\n");
  index = 0;
  for (i = 0; i < (1 << 18); i++) {
    fprintf(f, "  ");
    for (j = 0; j < 4; j++) {
      fprintf(f, "0x%08X, ", lwe_a_transpose[index++]);
    }
    fprintf(f, "\n");
  }
  fprintf(f, "};\n#endif /* _LWE_A_H_ */");
  
  fclose(f);
  return (0);
}
