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

// s (N_BAR x N)
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

// s (N_BAR x N)
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
  lwe_key_round(in, LWE_N_BAR * LWE_N_BAR, 32 - LWE_EXTRACTED_BITS);
  // out should have enough space for the key
  lwe_pack(out, LWE_KEY_BITS >> 3, in, LWE_N_BAR * LWE_N_BAR,
           LWE_EXTRACTED_BITS);
}

// <.>_2
void lwe_crossround2(unsigned char *out, const uint32_t *in) {
  int i;
  // out should have enough space for N_BAR * N_BAR bits
  memset((unsigned char *)out, 0, LWE_REC_HINT_LENGTH);

  uint32_t whole = 1 << (32 - LWE_EXTRACTED_BITS);
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

void lwe_reconcile(unsigned char *out, uint32_t *w, const unsigned char *hint) {
  lwe_reconcile_ct(out, w, hint);
}

void lwe_reconcile_ct(unsigned char *out, uint32_t *w,
                      const unsigned char *hint) {
  lwe_key_round_hints(w, LWE_N_BAR * LWE_N_BAR, 32 - LWE_EXTRACTED_BITS, hint);
  lwe_pack(out, LWE_KEY_BITS >> 3, w, LWE_N_BAR * LWE_N_BAR,
           LWE_EXTRACTED_BITS);
}

// multiply by s on the right, round-and-truncate
int lwe_key_gen_server(unsigned char *out, const uint32_t *a, const uint32_t *s,
                       const uint32_t *e) {
  // a (N x N)
  // s,e (N x N_BAR)
  // out = as + e (N x N_BAR)
  size_t i, j, k, index = 0;

  uint32_t *s_transpose =
      (uint32_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(uint32_t));
  if (s_transpose == NULL) {
    LWEKEXerr(LWEKEX_F_KEY_GEN_SERVER, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  uint32_t *out_unpacked =
      (uint32_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(uint32_t));
  if (out_unpacked == NULL) {
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

      out_unpacked[index] = sum;
      index++;
    }
  }
  lwe_key_round(out_unpacked, LWE_N * LWE_N_BAR, LWE_TRUNCATED_BITS);
  lwe_pack(out, LWE_PUB_LENGTH, out_unpacked, LWE_N * LWE_N_BAR,
           32 - LWE_TRUNCATED_BITS);

  OPENSSL_cleanse(out_unpacked, LWE_N_BAR * LWE_N * sizeof(uint32_t));
  OPENSSL_free(out_unpacked);

  OPENSSL_cleanse(s_transpose, LWE_N_BAR * LWE_N * sizeof(uint32_t));
  OPENSSL_free(s_transpose);

  return 1;
}

// multiply by s' on the left, round-and-truncate
int lwe_key_gen_client(unsigned char *out, const uint32_t *a_transpose,
                       const uint32_t *s, const uint32_t *e) {
  // a (N x N)
  // s',e' (N_BAR x N)
  // out = s'a + e' (N_BAR x N)

  uint32_t *out_unpacked =
      (uint32_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(uint32_t));
  if (out_unpacked == NULL) {
    LWEKEXerr(LWEKEX_F_KEY_GEN_CLIENT, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  int i, j, k, index = 0;
  for (k = 0; k < LWE_N_BAR; k++) {
    for (i = 0; i < LWE_N; i++) {
      uint32_t sum = e[index];

      for (j = 0; j < LWE_N; j++)
        sum += s[k * LWE_N + j] * a_transpose[i * LWE_N + j];

      out_unpacked[index] = sum;

      index++;
    }
  }

  lwe_key_round(out_unpacked, LWE_N * LWE_N_BAR, LWE_TRUNCATED_BITS);
  lwe_pack(out, LWE_PUB_LENGTH, out_unpacked, LWE_N * LWE_N_BAR,
           32 - LWE_TRUNCATED_BITS);

  OPENSSL_cleanse(out_unpacked, LWE_N_BAR * LWE_N * sizeof(uint32_t));
  OPENSSL_free(out_unpacked);

  return 1;
}

// multiply by s on the left
void lwe_key_derive_client(uint32_t *out, const uint32_t *b, const uint32_t *s,
                           const uint32_t *e) {
  // b (N x N_BAR)
  // s (N_BAR x N)
  // e (N_BAR x N_BAR)
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
  // b (N_BAR x N)
  // s (N x N_BAR)
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
void lwe_key_round_hints(uint32_t *vec, const size_t length, const int b,
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
    // printf("rounding 0x%08X (remainder = 0x%08X) ", vec[i], remainder);
    if ((remainder >= quarter) &&
        (remainder < three_quarters)) {  // use the hint
      unsigned char h = (hint[i / 8] >> (i % 8)) % 2;
      switch (h) {
        case 0:
          // printf("down ");
          vec[i] = vec[i] & negmask;  // round down
          break;
        case 1:
          // printf("up ");
          vec[i] = (vec[i] + whole - 1) & negmask;  // round up
          break;
      }
    } else {
      // printf("to the nearest ");
      vec[i] = (vec[i] + half) & negmask;  // round to the nearest
    }
    // printf(" result =  0x%08X\n", vec[i]);
  }
}

// Add uniform noise to the lsb bits of b
int lwe_add_unif_noise(uint32_t *b, const size_t blen, const unsigned char lsb) {
  size_t packed_len = LWE_DIV_ROUNDUP(blen * lsb, 8);
  unsigned char *noise_packed =
      (unsigned char *)OPENSSL_malloc(packed_len);
  if (noise_packed == NULL) {
    LWEKEXerr(LWEKEX_F_ADD_UNIF_NOISE, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  uint32_t *noise_unpacked =
      (uint32_t *)OPENSSL_malloc(blen * sizeof(uint32_t));
  if (noise_unpacked == NULL) {
    LWEKEXerr(LWEKEX_F_ADD_UNIF_NOISE, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  
  RANDOM_VARS;
  RANDOMBUFF(noise_packed, packed_len);  // fill the array with noise
  lwe_unpack(noise_unpacked, blen, noise_packed, packed_len, lsb); 
  
  uint32_t half = (1 << lsb) / 2;  // same as 1 << (lsb-1) except when lsb == 0 
  size_t i = 0;
  for(i = 0; i < blen; i++)
    b[i] += (noise_unpacked[i] >> (32 - lsb)) - half;
 
  OPENSSL_cleanse(noise_unpacked, blen * sizeof(uint32_t));
  OPENSSL_free(noise_unpacked);

  OPENSSL_cleanse(noise_packed, packed_len);
  OPENSSL_free(noise_packed); 
  
  return 1;
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
    /*
    in: |        |        |********|********|
                          ^
                          j
    w : |****    |
            ^
           bits
    out:|**|**|**|**|**|**|**|**|* |
                                ^^
                                ib
    */
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
}

// Unpack the input char vector into a uint32_t output vector, copying msb bits
// for each output element from input. outlen must be at least ceil(inlen * 8 /
// msb).
void lwe_unpack(uint32_t *out, const size_t outlen, const unsigned char *in,
                const size_t inlen, const unsigned char msb) {
  memset(out, 0, outlen * sizeof(uint32_t));

  int i = 0;               // whole dwords already filled in
  int j = 0;               // whole bytes already copied
  unsigned char w = 0;     // the leftover, not yet copied
  unsigned char bits = 0;  // the number of msb bits of w
  while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
    /*
    in: |  |  |  |  |  |  |**|**|...
                          ^
                          j
    w : |* |
         ^
         bits
    out:|*****   |*****   |***     |        |...
                          ^  ^
                          i  b
    */
    unsigned char b = 0;  // bits in out[i] already filled in
    while (b < msb) {
      int nbits = bits > (msb - b) ? msb - b : bits;  // =min(msb - b, bits);
      unsigned char t = w >> (8 - nbits);  // the bits to copy from w to out
      out[i] = out[i] + (t << (32 - b - nbits));
      w <<= nbits;
      b += nbits;
      bits -= nbits;

      if (bits == 0) {
        if (j < inlen) {
          w = in[j];
          bits = 8;
          j++;
        } else
          break;  // the input vector is exhausted
      }
    }
    if (b == msb) {  // out[i] is filled in
      i++;
      b = 0;
    }
  }
}