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
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project", and "Google" must not
 * be used to
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwe.h"
#include "lwe_a.h"
#include "lwe_table.h"
#include "lwe_noise.h"

/************************
 * TABLE-BASED SAMPLING *
 ***********************/

/* Returns 0 if a >= b
 * Returns 1 if a < b
 * Where a and b are both 3-limb 64-bit integers.
 * This function runs in constant time.
 */
int cmplt_ct(uint64_t *a, uint64_t *b) {
  int m;
  m = a[0] >= b[0];
  m = (a[1] >= b[1]) | ((a[1] == b[1]) & m);
  m = (a[2] >= b[2]) | ((a[2] == b[2]) & m);
  return (m == 0);
}

static uint32_t single_sample_table(uint64_t *in) {
  int i = 0;

  while (cmplt_ct(lwe_table[i], in))  // ~3.5 comparisons in expectation
    i++;

  return i;
}

/* Constant time version. */
static uint32_t single_sample_table_ct(uint64_t *in) {
  uint32_t index = 0, i;

  for (i = 0; i < LWE_MAX_NOISE; i++) {
    uint32_t mask1, mask2;
    mask1 = cmplt_ct(in, lwe_table[i]);
    mask1 = (uint32_t)(0 - (int32_t)mask1);
    mask2 = (~mask1);
    index = ((index & mask1) | (i & mask2));
  }
  return index;
}

/**************************
 * BINOMIAL APPROXIMATION *
 **************************/

static uint32_t single_sample_binomial(uint64_t *in) {
  int i = 0;

  while (cmplt_ct(lwe_table[i], in))  // ~3.5 comparisons in expectation
    i++;

  return i;
}

/* Constant time version. */
static uint32_t single_sample_binomial_ct(uint64_t *in) {
  uint32_t index = 0, i;

  for (i = 0; i < LWE_MAX_NOISE; i++) {
    uint32_t mask1, mask2;
    mask1 = cmplt_ct(in, lwe_table[i]);
    mask1 = (uint32_t)(0 - (int32_t)mask1);
    mask2 = (~mask1);
    index = ((index & mask1) | (i & mask2));
  }
  return index;
}
