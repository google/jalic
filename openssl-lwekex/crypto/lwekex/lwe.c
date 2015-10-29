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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "lwe_a.h"
#include "lwe.h"
#include "lwe_table.h"

#define setbit(a, x) \
  ((a)[(x) / 8] |= (((unsigned char)1) << (unsigned char)((x) % 8)))
#define getbit(a, x) (((a)[(x) / 8] >> (unsigned char)((x) % 8)) & 1)
#define clearbit(a, x) \
  ((a)[(x) / 8] &=     \
   ((~((unsigned char)0)) - (((unsigned char)1) << (unsigned char)((x) % 8))))

#define RANDOM192(c) \
  c[0] = RANDOM64;   \
  c[1] = RANDOM64;   \
  c[2] = RANDOM64;

/* Returns 0 if a >= b
 * Returns 1 if a < b
 * Where a and b are both 3-limb 64-bit integers.
 * This function runs in constant time.
 */
static int cmplt_ct(uint64_t *a, uint64_t *b) {
  int m;
  m = a[0] >= b[0];
  m = (a[1] >= b[1]) | ((a[1] == b[1]) & m);
  m = (a[2] >= b[2]) | ((a[2] == b[2]) & m);
  return (m == 0);
}

static uint32_t single_sample(uint64_t *in) {
  int i = 0;

  while (cmplt_ct(lwe_table[i], in))  // ~3.5 comparisons in expectation
    i++;

  return i;
}

/* Constant time version. */
static uint32_t single_sample_ct(uint64_t *in) {
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

void lwe_sample_n_ct(uint32_t *s, int n) {
  RANDOM_VARS;
  int j, k, index;
  int number_of_batches = (n + 63) / 64;  // ceil(n / 64)
  for (k = 0; k < number_of_batches; k++) {
    uint64_t r = RANDOM64;
    for (j = 0; j < 64; j++) {
      index = k * 64 + j;
      if (index >= n) {
        return;
      }
      uint64_t rnd[3];
      int32_t m;
      uint32_t t;
      RANDOMBUFF((unsigned char *)rnd, 24);
      m = (r & 1);
      r >>= 1;
      m = 2 * m - 1;
      // use the constant time version single_sample
      s[index] = single_sample_ct(rnd);
      t = 0xFFFFFFFF - s[index];
      s[index] = ((t & (uint32_t)m) | (s[index] & (~((uint32_t)m))));
    }
  }
}

// s (3 x 1024)
void lwe_sample_ct(uint32_t *s) {
  RANDOM_VARS;
  int i, j, k, index = 0;
  for (k = 0; k < LWE_N_BAR; k++) {
    for (i = 0; i < (LWE_N >> 6); i++) {  // 1024 >> 6 = 16
      uint64_t r = RANDOM64;
      for (j = 0; j < 64; j++) {
        uint64_t rnd[3];
        int32_t m;
        uint32_t t;
        RANDOM192(rnd);
        m = (r & 1);
        r >>= 1;
        m = 2 * m - 1;
        // use the constant time version single_sample
        s[index] = single_sample_ct(rnd);
        // printf("    * %i: 0x%08X\n", index, s[index]);
        t = 0xFFFFFFFF - s[index];
        s[index] = ((t & (uint32_t)m) | (s[index] & (~((uint32_t)m))));
        index++;
      }
    }
  }
}

void lwe_sample_n(uint32_t *s, int n) {
  RANDOM_VARS;
  int j, k, index = 0;
  int number_of_batches = (n + 63) / 64;  // ceil(n / 64)
  for (k = 0; k < number_of_batches; k++) {
    uint64_t r = RANDOM64;
    for (j = 0; j < 64; j++) {
      uint64_t rnd[3];
      int32_t m;
      RANDOM192(rnd);
      m = (r & 1);
      r >>= 1;
      m = 2 * m - 1;
      s[index] = single_sample(rnd);
      if (m == -1) {
        s[index] = 0xFFFFFFFF - s[index];
      }
      index++;
      if (index >= n) {
        return;
      }
    }
  }
}

// s (3 x 1024)
void lwe_sample(uint32_t *s) {
  RANDOM_VARS;
  int i, j, k, index = 0;
  for (k = 0; k < LWE_N_BAR; k++) {
    for (i = 0; i < (LWE_N >> 6); i++) {  // 1024 >> 6 = 16
      uint64_t r = RANDOM64;
      uint64_t rnd[3 * 64];
      RANDOMBUFF((unsigned char *)rnd, sizeof(rnd));
      for (j = 0; j < 64; j++) {
        s[index] = single_sample(rnd + 3 * j);
        if ((r >> j) & 1) {
          s[index] =
              -s[index];  // since s is unsigned, equivalent to 2^32 - s[index]
        }
        index++;
      }
    }
  }
}

// [.]_2
void lwe_round2(unsigned char *out, uint32_t *in) {
  lwe_key_round(in, LWE_N_BAR * LWE_N_BAR, 32 - LWE_REC_BITS);

  // out should have enough space for the key
  memset((unsigned char *)out, 0, LWE_KEY_LENGTH >> 3);

  lwe_pack(out, LWE_KEY_LENGTH >> 3, in, LWE_N_BAR * LWE_N_BAR, LWE_REC_BITS);
}

// <.>_2
void lwe_crossround2(unsigned char *out, const uint32_t *in) {
  int i;
  // out should have enough space for N_BAR * N_BAR bits
  memset((unsigned char *)out, 0, LWE_REC_LENGTH);
  
  uint32_t whole = 1 << (32 - LWE_REC_BITS);
  uint32_t half = whole >> 1;
  uint32_t mask = whole - 1;

  for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
    uint32_t remainder = in[i] & mask;
    out[i / 8] += (remainder >= half) << (i % 8);
  }
/*
    // q/4 to q/2 and q/2 to q
    if ((in[i] >> (31 - LWE_REC_BITS)) & 1) {
      setbit(out, i);
    }
*/
}

void lwe_rec(unsigned char *out, uint32_t *w, const unsigned char *b) {
  lwe_rec_ct(out, w, b);
}

void lwe_rec_ct(unsigned char *out, uint32_t *w, const unsigned char *b) {
  lwe_key_round_directed(w, LWE_N_BAR * LWE_N_BAR, 32 - LWE_REC_BITS, b);
  lwe_pack(out, LWE_KEY_LENGTH >> 3, w, LWE_N_BAR * LWE_N_BAR, LWE_REC_BITS);
}

// multiply by s on the right
int lwe_key_gen_server(uint32_t *out, const uint32_t *a, const uint32_t *s,
                       const uint32_t *e) {
  // a (1024 x 1024)
  // s,e (1024 x 3)
  // out = as + e (1024 x 3)
  size_t i, j, k, index = 0;

  uint32_t *s_transpose =
      NULL;  // A temporary copy of s in the column-major order

  s_transpose =
      (uint32_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(uint32_t));
  if (s_transpose == NULL) {
    LWEKEXerr(LWEKEX_F_KEY_GEN_SERVER, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  for (j = 0; j < LWE_N; j++)
    for (k = 0; k < LWE_N_BAR; k++)
      s_transpose[k * LWE_N + j] = s[j * LWE_N_BAR + k];

  for (i = 0; i < LWE_N; i++) {
    for (k = 0; k < LWE_N_BAR; k++) {
      uint32_t sum = e[index];
      for (j = 0; j < LWE_N; j++)
        sum += a[i * LWE_N + j] * s_transpose[k * LWE_N + j];

      out[index] = sum;
      index++;
    }
  }
  lwe_key_round(out, LWE_N * LWE_N_BAR, LWE_KEY_TRUNCATE);

  OPENSSL_cleanse(s_transpose, LWE_N_BAR * LWE_N * sizeof(uint32_t));
  OPENSSL_free(s_transpose);

  return 1;
}

// multiply by s on the left
void lwe_key_gen_client(uint32_t *out, const uint32_t *a_transpose,
                        const uint32_t *s, const uint32_t *e) {
  // a (1024 x 1024)
  // s',e' (3 x 1024)
  // out = s'a + e' (3 x 1024)
  int i, j, k, index = 0;
  for (k = 0; k < LWE_N_BAR; k++) {
    for (i = 0; i < LWE_N; i++) {
      uint32_t sum = e[index];

      for (j = 0; j < LWE_N; j++)
        sum += s[k * LWE_N + j] * a_transpose[i * LWE_N + j];

      out[index] = sum;

      index++;
    }
  }

  lwe_key_round(out, LWE_N_BAR * LWE_N, LWE_KEY_TRUNCATE);
}

// multiply by s on the left
void lwe_key_derive_client(uint32_t *out, const uint32_t *b, const uint32_t *s,
                           const uint32_t *e) {
  // b (1024 x 3)
  // s (3 x 1024)
  // e (3 x 3)
  // out = sb + e
  int i, j, k;
  for (k = 0; k < LWE_N_BAR; k++) {
    for (i = 0; i < LWE_N_BAR; i++) {
      out[k * LWE_N_BAR + i] = e[k * LWE_N_BAR + i];
      for (j = 0; j < LWE_N; j++) {
        out[k * LWE_N_BAR + i] += s[k * LWE_N + j] * b[j * LWE_N_BAR + i];
      }
    }
  }
}

// multiply by s on the right
void lwe_key_derive_server(uint32_t *out, const uint32_t *b,
                           const uint32_t *s) {
  // b (3 x 1024)
  // s (1024 x 3)
  // out = bs
  int i, j, k;
  for (i = 0; i < LWE_N_BAR; i++) {
    for (j = 0; j < LWE_N_BAR; j++) {
      out[i * LWE_N_BAR + j] = 0;
      for (k = 0; k < LWE_N; k++) {
        out[i * LWE_N_BAR + j] += b[i * LWE_N + k] * s[k * LWE_N_BAR + j];
      }
    }
  }
}

// round all elements of a vector to the nearest multiple of 2^b
void lwe_key_round(uint32_t *vec, const size_t length, const int b) {
  int i;
  uint32_t negmask = ~((1 << b) - 1);
  uint32_t half = b > 0 ? 1 << (b - 1) : 0;
  for (i = 0; i < length; i++) vec[i] = (vec[i] + half) & negmask;
}

// Round all elements of a vector to the multiple of 2^b, with a hint for the 
// direction of rounding when close to the boundary.
void lwe_key_round_directed(uint32_t *vec, const size_t length, const int b,
                            const unsigned char *hint) {
  int i;
  uint32_t whole = 1 << b;
  uint32_t mask = whole - 1;
  uint32_t negmask = ~mask;
  uint32_t half = 1 << (b - 1);
  uint32_t quarter = 1 << (b - 2);
  uint32_t three_quarters = 3 * (1 << (b - 2));
  
  for (i = 0; i < length; i++) {
    uint32_t remainder = vec[i] & mask;
    if((remainder >= quarter) && (remainder < three_quarters)) { // use the hint   
      switch ((hint[i / 8] >> (i % 8)) % 2) {
        case 0:
          vec[i] = vec[i] & negmask;
          break;
        case 1:
          vec[i] = (vec[i] + whole - 1) & negmask;
          break;
      }
    } else
      vec[i] = (vec[i] + half) & negmask;
  }
}

// Pack the input uint32 vector into a char output vector, copying msb bits
// from each input element. If inlen * msb / 8 > outlen, only outlen * 8 bits
// are copied.
void lwe_pack(unsigned char *out, const size_t outlen, const uint32_t *in,
              const size_t inlen, const unsigned char msb) {
  
  memset((unsigned char *)out, 0, outlen); 
  
  int i = 0;               // whole bytes already filled in
  int j = 0;               // whole uint32_t already copied
  uint32_t w = 0;          // the leftover, not yet copied
  unsigned char bits = 0;  // the number of msb in w

  while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
    unsigned char b = 0;  // bits in out[i] already filled in
    while (b < 8) {
      int nbits = bits > (8 - b) ? 8 - b : bits;  // min(8 - b, bits);
      unsigned char t = w >> (32 - nbits);  // the bits to copy from w to out
      out[i] = out[i] + (t << (8 - b - nbits));
      w <<= nbits;
      b += nbits;
      bits -= nbits;

      if (bits == 0) {
        if (j < inlen) {
          w = in[j];
          bits = msb;
          j++;
        } else
          break;  // the input vector is exhausted
      }
    }
    if (b == 8) {  // out[i] is filled in
      i++;
      b = 0;
    }
  }
/*
  printf(
      "Copied %d bytes, %d bits from each element, using %d double words from "
      "the input; %d bits are not copied\n",
      i, msb, j, bits);
  
  for(i = 0; i < 7; i++)
    printf("%08x\n", in[i]);
  
  for(i = 0; i < 16; i++)
    printf("%02x\n", out[i]);
*/
}