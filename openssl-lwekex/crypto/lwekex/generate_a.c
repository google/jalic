/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project and Google Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project", and "Google" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <openssl/rand.h>

uint32_t random32() {
  uint32_t b;
  int r = RAND_bytes((unsigned char *)&b, 4);
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
  fprintf(f,
          "/*\nCopyright 2015 Google Inc. All Rights Reserved.\n\nAuthor: "
          "Valeria Nikolaenko (nikolaenko@google.com)\nAuthor: "
          "Ananth Raghunathan (pseudorandom@google.com)\nAuthor: "
          "Ilya Mironov (mironov@google.com)\n*/\n");
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
