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
#include "lwe_noise.h"
#include "lwe_table.h"

#define CONST_TIME_TERNARY_IF(COND, V1, V2) \
  ((COND) * (V1) + (1 - (COND)) * (V2))
#define CONST_TIME_TERNARY_IF_ALT32(COND, V1, V2) \
  (((V1) & ((uint32_t)(0 - (int32_t)(COND)))) |   \
   ((V2) & ((uint32_t)((int32_t)(COND)-1))))
#define CONST_TIME_TERNARY_IF_ALT8(COND, V1, V2) \
  (((V1) & ((uint8_t)(0 - (int8_t)(COND)))) |    \
   ((V2) & ((uint8_t)((int8_t)(COND)-1))))

/************************
 * TABLE-BASED SAMPLING *
 ***********************/

int cmplt_ct(const uint64_t *a, const uint64_t *b) {
  /* Returns 0 if a >= b
   * Returns 1 if a < b
   * Inputs a and b are 3-limb 64-bit integers.
   * Runs in constant time.
   */
  int m;
  m = a[0] >= b[0];
  m = (a[1] >= b[1]) | ((a[1] == b[1]) & m);
  m = (a[2] >= b[2]) | ((a[2] == b[2]) & m);
  return (m == 0);
}

uint32_t single_sample_table(const uint64_t *in) {
  /* Outputs a single sample from the noise distribution using 24 bytes of
   * uniform randomness provided in the input vector. The noise distribution
   * is specified by its cdf in lwe_table.
   * Variable running time.
   */

  size_t i = 0;

  while (cmplt_ct(lwe_table[i], in))  // ~3.5 comparisons in expectation
    i++;

  return i;
}

uint32_t single_sample_table_ct(const uint64_t *in) {
  /* Outputs a single sample from the noise distribution using 24 bytes of
   * uniform randomness provided in the input vector. The noise distribution
   * is specified by its cdf in lwe_table.
   * Runs in constant time.
   */

  uint32_t index = 0, i;

  for (i = 0; i < LWE_MAX_NOISE; i++) {
    /*
    uint32_t mask1, mask2;
    mask1 = cmplt_ct(in, lwe_table[i]);
    mask1 = (uint32_t)(0 - (int32_t)mask1);
    mask2 = (~mask1);
    index = ((index & mask1) | ((i + 1) & mask2));
    */
    int c = cmplt_ct(in, lwe_table[i]);
    index = CONST_TIME_TERNARY_IF_ALT32(c, index, i + 1);
  }
  return index;
}

void lwe_sample_n_table(uint32_t *s, const size_t n) {
  // Fills vector s with n samples from the noise distribution specified by
  // its cdf in lwe_table.

  RANDOM_VARS;
  size_t k = 0;
  size_t number_of_batches = (n + 63) / 64;  // ceil(n / 64)
  for (k = 0; k < number_of_batches; k++) {
    uint64_t r = RANDOM64;
    uint64_t rnd[3 * 64];
    RANDOMBUFF((unsigned char *)rnd, sizeof(rnd));
    int bound = (k + 1) * 64 < n ? 64 : n - k * 64;  // min(64, n - k * 64)
    size_t i = 0;
    for (i = 0; i < bound; i++) {
#if LWE_SAMPLE_CONST_TIME_LEVEL > 0
      uint32_t sample = single_sample_table_ct(rnd + 3 * i);
      s[k * 64 + i] = CONST_TIME_TERNARY_IF(r & 1, sample, -sample);
#else
      s[k * 64 + i] = single_sample_table(rnd + 3 * i);
      if (r & 1) s[k * 64 + i] = -s[k * 64 + i];
#endif
      r >>= 1;
    }
  }
}

/**************************
 * BINOMIAL APPROXIMATION *
 **************************/

uint64_t count_bits8(uint64_t x) {
  // Count bits set in each byte of x using the "SWAR" algorithm.
  x -= (x >> 1) & 0x5555555555555555;
  x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333);
  x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f;
  return x;
}

void lwe_sample_n_binomial24(uint32_t *s, const size_t n) {
  // Fills vector s with n samples from the noise distribution. The noise
  // distribution is shifted binomial B(24, .5) - 12.
  // Runs in constant time. Can be sped up with compiler intrinsics.

  size_t rndlen = 3 * n;  // 24 bits of uniform randomness per output element
  if (rndlen % 8 != 0)
    rndlen += 8 - (rndlen % 8);  // force rndlen be divisible by 8

  uint64_t *rnd = (uint64_t *)OPENSSL_malloc(rndlen);
  if (rnd == NULL) {
    LWEKEXerr(LWEKEX_F_LWE_SAMPLE_N_BINOMIAL24, ERR_R_MALLOC_FAILURE);
    return;
  }

  RANDOM_VARS;
  RANDOMBUFF((unsigned char *)rnd, rndlen);

  uint64_t *ptr_rnd =
      rnd;  // processes 3 rnd entries for each 8 output elements

  size_t i, j;
  for (i = 0; i < n; i += 8) {
    uint64_t sum = count_bits8(ptr_rnd[0]) + count_bits8(ptr_rnd[1]) +
                   count_bits8(ptr_rnd[2]);
    // each byte of sum holds the count of the total number of bits set to 1 in
    // the corresponding bytes of rnd[0], rnd[1], rnd[2].

    size_t bound = i + 8 < n ? 8 : n - i;  // min(8, n - i)
    for (j = 0; j < bound; j++)
      s[i + j] = (uint32_t)((sum >> (j * 8)) & 0xFF) - 12;

    ptr_rnd += 3;
  }
  OPENSSL_cleanse(rnd, rndlen);
  OPENSSL_free(rnd);
}

uint32_t count_bits32(uint32_t x) {
  /* Count bits set to 1 using the "SWAR" algorithm.
   * Can be replaced with __builtin_popcount(x) that resolves either to a
   * a hardware instruction or a library implementation.
   */
  x -= (x >> 1) & 0x55555555;
  x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
  x = (x + (x >> 4)) & 0x0f0f0f0f;
  x += x >> 8;
  x += x >> 16;
  return x & 0x3F;  // Returned answer is <= 32 which is at most 6 bits long.
}

void lwe_sample_n_binomial32(uint32_t *s, const size_t n) {
  // Fills vector s with n samples from the noise distribution. The noise
  // distribution is shifted binomial B(32, .5) - 16.
  // Runs in constant time. Can be sped up with compiler intrinsics.

  size_t rndlen = 4 * n;  // 32 bits of uniform randomness per output element
  uint32_t *rnd = (uint32_t *)OPENSSL_malloc(rndlen);
  if (rnd == NULL) {
    LWEKEXerr(LWEKEX_F_LWE_SAMPLE_N_BINOMIAL32, ERR_R_MALLOC_FAILURE);
    return;
  }
  RANDOM_VARS;
  RANDOMBUFF((unsigned char *)rnd, rndlen);
  size_t i;
  for (i = 0; i < n; i++) s[i] = count_bits32(rnd[i]) - 16;
  OPENSSL_cleanse(rnd, rndlen);
  OPENSSL_free(rnd);
}

/****************
 * ALIAS METHOD *
 ****************/
/* Good appoximation to the rounded Gaussian with sigma^2 = 6. The Renyi
 * divergence of order 75 between the two is ~1.0008927.
 * The range of the distribution is [0..8]. Requires 4 bits to sample the bin
 * and 7 bits to sample the threshold.
 */
static const uint8_t ALIAS_METHOD_BINS = 16;

static const uint8_t ALIAS_METHOD_THRESHOLDS_S6[] = {
    76, 128, 105, 60, 110, 85, 34, 12, 3, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t ALIAS_METHOD_ALIASES_S6[] = {1, 1, 1, 4, 1, 1, 1, 2,
                                                  1, 2, 1, 0, 3, 2, 0, 3};

/* Good appoximation to the rounded Gaussian with sigma^2 = 8. The Renyi
 * divergence of order 50 between the two is ~1.000565.
 * The range of the distribution is [0..10]. Requires 4 bits to sample the bin
 * and 7 bits to sample the threshold.
 */
const uint8_t ALIAS_METHOD_THRESHOLDS_S8[16] = {
    105, 116, 77, 128, 74, 122, 62, 28, 11, 4, 1, 0, 0, 0, 0, 0};
const uint8_t ALIAS_METHOD_ALIASES_S8[16] = {3, 4, 3, 3, 0, 1, 1, 1,
                                             2, 1, 2, 3, 0, 1, 2, 4};

#if (ALIAS_METHOD_THRESHOLDS & 0x0F) != 0 || (ALIAS_METHOD_ALIASES & 0x0F) != 0
#error "Static constants are not aligned. A potential cache-timing attack."
#endif

typedef struct {
  /* The struct used in the sampling process; can be replaced with bit
   * manipulation routines. Important: its size must be exactly 3 bytes
   * (guaranteed by the packed attribute). Not important: the exact
   * ordering of bit-fields.
   */
  uint8_t threshold1 : 7;
  uint8_t bin1 : 4;
  uint8_t sign1 : 1;
  uint8_t threshold2 : 7;
  uint8_t bin2 : 4;
  uint8_t sign2 : 1;
} __attribute__((__packed__)) three_bytes_packed;

void lwe_sample_n_alias(uint32_t *s, size_t n) {
  /* Fills vector s with n samples from the noise distribution. The noise
   * distribution is specified by its alias method structures.
   */

  size_t rndlen = 3 * n / 2;  // 12 bits of unif randomness per output element
  if (rndlen % 4 != 0)
    rndlen += 4 - (rndlen % 4);  // force rndlen be divisible by 4

  uint8_t *rnd = (uint8_t *)OPENSSL_malloc(rndlen);
  if (rnd == NULL) {
    LWEKEXerr(LWEKEX_F_LWE_SAMPLE_N_ALIAS, ERR_R_MALLOC_FAILURE);
    return;
  }

  RANDOM_VARS;
  RANDOMBUFF((unsigned char *)rnd, rndlen);

  size_t i;
  OPENSSL_assert(sizeof(three_bytes_packed) == 3);

  for (i = 0; i < n; i += 2) {  // two output elements at a time
    uint8_t bin1, threshold1, sample1 = ALIAS_METHOD_BINS;
    uint8_t bin2, threshold2, sample2 = ALIAS_METHOD_BINS;
    int8_t sign1, sign2;

    /* Use 24 bits of u to sample two noise values using the alias method as
     * follows:
     * u: [byte 0] [byte 1] [byte 2]
     *    01234567 89012345 67890123
     *    aaaaaaab bbbcdddd dddeeeef
     * where:
     *  bbbb    selects the bin for the first sample
     *  aaaaaaa sets the threshold of the first sample
     *  c       is the sign of the first sample
     *  eeee    selects the bin for the second sample
     *  ddddddd sets for the threshold of the second sample
     *  f       is the sign of the second sample
     */

    /* Implementation based on bit manipulation
    uint32_t u = *(uint32_t *)(rnd + 3 * i / 2);

    bin1 = (u >> 7) & 0xF;        // 4 bits
    threshold1 = u & 0x7F;        // 7 bits
    sign1 = ((u >> 10) & 2) - 1;  // = shift by 11, multiply by 2, substract 1

    bin2 = (u >> 19) & 0xF;         // 4 bits
    threshold2 = (u >> 12) & 0x7F;  // 7 bits
    sign2 = ((u >> 22) & 2) - 1;    // = shift by 23, multiply by 2, substract 1
    */

    /* Implementation based on a bit-field structure:
     *  - slightly more compact and readable;
     *  - more compiler-dependent. In particular, __attribute__((packed))
     *    is gcc-specific.
     */
    three_bytes_packed *ptr_packed = (three_bytes_packed *)(rnd + 3 * i / 2);
    bin1 = ptr_packed->bin1;
    threshold1 = ptr_packed->threshold1;
    sign1 = 2 * ptr_packed->sign1 - 1;

    bin2 = ptr_packed->bin2;
    threshold2 = ptr_packed->threshold2;
    sign2 = 2 * ptr_packed->sign2 - 1;

#if LWE_SAMPLE_CONST_TIME_LEVEL >= 2
    /* Super-constant timing: the tables of thresholds and aliases are ingested
     * for every sample.
     */
    uint8_t b1, b2;
    size_t j;
    for (j = 0; j < ALIAS_METHOD_BINS; j++) {
      b1 = CONST_TIME_TERNARY_IF(ALIAS_METHOD_THRESHOLDS[j] < threshold1,
                                 ALIAS_METHOD_ALIASES[j], j);
      sample1 = CONST_TIME_TERNARY_IF(j == bin1, b1, sample1);

      b2 = CONST_TIME_TERNARY_IF(ALIAS_METHOD_THRESHOLDS[j] < threshold2,
                                 ALIAS_METHOD_ALIASES[j], j);
      sample2 = CONST_TIME_TERNARY_IF(j == bin2, b2, sample2);
    }

#else
#if LWE_SAMPLE_CONST_TIME_LEVEL >= 1
    /* Constant time except that table lookups have variable access
     * pattern. (Tables most likely fit into a single cacheline.)
     */
    sample1 = CONST_TIME_TERNARY_IF(ALIAS_METHOD_THRESHOLDS[bin1] < threshold1,
                                    ALIAS_METHOD_ALIASES[bin1], bin1);
    sample2 = CONST_TIME_TERNARY_IF(ALIAS_METHOD_THRESHOLDS[bin2] < threshold2,
                                    ALIAS_METHOD_ALIASES[bin2], bin2);
#else
    // No expectation of constant timing!
    sample1 = ALIAS_METHOD_THRESHOLDS[bin1] < threshold1
                  ? ALIAS_METHOD_ALIASES[bin1]
                  : bin1;
    sample2 = ALIAS_METHOD_THRESHOLDS[bin2] < threshold2
                  ? ALIAS_METHOD_ALIASES[bin2]
                  : bin2;
#endif

#endif
    s[i] = sign1 * sample1;

    if (i + 1 < n) s[i + 1] = sign2 * sample2;
  }

  OPENSSL_cleanse(rnd, rndlen);
  OPENSSL_free(rnd);
}
