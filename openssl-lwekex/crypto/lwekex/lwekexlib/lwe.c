/*
Copyright 2015 Google Inc. All Rights Reserved.

Author: nikolaenko@google.com (Valeria Nikolaenko)
Author: pseudorandom@google.com (Ananth Raghunathan)
Author: mironov@google.com (Ilya Mironov)
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "lwe.h"

#include "lwe_table.h"

#define setbit(a,x) ((a)[(x)/8] |= (((unsigned char) 1) << (unsigned char) ((x)%8)))
#define getbit(a,x) (((a)[(x)/8] >> (unsigned char) ((x)%8)) & 1)
#define clearbit(a,x) ((a)[(x)/8] &= ((~((unsigned char) 0)) - (((unsigned char) 1) << (unsigned char) ((x)%8))))

#define RANDOM192(c) c[0] = RANDOM64; c[1] = RANDOM64; c[2] = RANDOM64

/* Returns 0 if a >= b
 * Returns 1 if a < b
 * Where a and b are both 3-limb 64-bit integers.
 * This function runs in constant time.
 */
static int cmplt_ct(uint64_t *a, uint64_t *b) {
  int m;
  m = (a[0] >= b[0]);
  m = ((a[1] >= b[1]) && (!(a[1] == b[1]) || m));
  m = ((a[2] >= b[2]) && (!(a[2] == b[2]) || m));
  return (m == 0);
}

static uint32_t single_sample(uint64_t *in) {
  uint32_t lower_index = 0, this_index = 32, upper_index = 64;
  int i;
  for (i = 0; i < 6; i++) {
    if (cmplt_ct(in, rlwe_table[this_index])) {
      upper_index = this_index;
    } else {
      lower_index = this_index;
    }
    this_index = (lower_index + upper_index) / 2;
  }
  return lower_index;
}

/* Constant time version. */
static uint32_t single_sample_ct(uint64_t *in) {
  uint32_t index = 0, i;

  for (i = 0; i < 52; i++) {
    uint32_t mask1, mask2;
    mask1 = cmplt_ct(in, rlwe_table[i]);
    mask1 = (uint32_t) (0 - (int32_t) mask1);
    mask2 = (~mask1);
    index = ((index & mask1) | (i & mask2));
  }
  return index;
}

void lwe_sample_n_ct(uint32_t *s, int n) {
  RANDOM_VARS;
  int j, k, index;
  int number_of_batches = (n + 63) / 64; // ceil(n / 64)
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
      RANDOM192(rnd);
      m = (r & 1);
      r >>= 1;
      m = 2 * m - 1;
      // use the constant time version single_sample
      s[index] = single_sample_ct(rnd);
      t = 0xFFFFFFFF - s[index];
      s[index] = ((t & (uint32_t) m) | (s[index] & (~((uint32_t) m))));
    }
  }
}

// s (12 x 1024)
void lwe_sample_ct(uint32_t *s) {
  RANDOM_VARS;
  int i, j, k, index = 0;
  for (k = 0; k < LWE_N_HAT; k++) {
    for (i = 0; i < (LWE_N >> 6); i++) { // 1024 >> 6 = 16
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
	s[index] = ((t & (uint32_t) m) | (s[index] & (~((uint32_t) m))));
	index++;
      }
    }
  }
}

void lwe_sample_n(uint32_t *s, int n) {
  RANDOM_VARS;
  int j, k, index = 0;
  int number_of_batches = (n + 63) / 64; // ceil(n / 64)
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

// s (12 x 1024)
void lwe_sample(uint32_t *s) {
  RANDOM_VARS;
  int i, j, k, index = 0;
  for (k = 0; k < LWE_N_HAT; k++) {
    for (i = 0; i < (LWE_N >> 6); i++) { // 1024 >> 6 = 16
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
      }
    }
  }
}

// [.]_2
void lwe_round2(unsigned char *out, const uint32_t *in) {
  int i, j, index = 0;

  // out should have enough space for 128-bits //NB!
  memset((unsigned char *)out, 0, LWE_KEY_LENGTH >> 3); // 128 >> 3 = 16

  // 1 iff between q/4 and 3*q/4
  for (i = 0; i < LWE_N_HAT * LWE_N_HAT; i++) {
    // if (in[i] >= 1073741824 && in[i] <= 3221225471) { // from rlwe
    // if (((in[i] >> 30) & 1) + ((in[i] >> 31) & 1) == 1) { // previous mechanism
    for (j = 0; j < LWE_REC_BITS; j++) {
      if (index >= LWE_KEY_LENGTH) {
	return;
      }
      if ((in[i] >> (32 - LWE_REC_BITS + j)) & 1) { // previous mechanism
	setbit(out, index);
      }
      index++;
    }
  }
}

/* Constant time version. */
// [.]_2
void lwe_round2_ct(unsigned char *out, const uint32_t *in) {
  int i, j, index;
  // out should have enough space for 128-bits //NB!
  memset((unsigned char *)out, 0, LWE_KEY_LENGTH >> 3);
  for (i = 0; i < LWE_N_HAT * LWE_N_HAT; i++) {
    // uint32_t b = (((in[i] >> 30) & 1) + ((in[i] >> 31) & 1)) & 1;
    for (j = 0; j < LWE_REC_BITS; j++) {
      index = i * LWE_REC_BITS + j;
      if (index >= LWE_KEY_LENGTH) {
	return;
      }
      uint32_t b = ((in[i] >> (32 - LWE_REC_BITS + j)) & 1);
      out[index / 8] |= (((unsigned char) b) << (unsigned char) (index % 8));
    }
    /*
    if (i < 5) {
      binary_printf(in[i], 32);
      printf(" -> ");
      binary_printf(out[0], 64);
      printf(" <- ");
      binary_printf(in[i] >> (32 - LWE_REC_BITS), LWE_REC_BITS);
      printf("\n");
    } */
  }
}

// <.>_2
void lwe_crossround2(unsigned char *out, const uint32_t *in) {
  int i;
  // out should have enough space for 1024-bits
  memset((unsigned char *)out, 0, LWE_KEY_LENGTH >> 3);

  // in (12 x 12)
  // take first 128 elements of in and convert them to bits
  for (i = 0; i < LWE_KEY_LENGTH; i++) {
    //q/4 to q/2 and q/2 to q
    if ((in[i] >> (31 - LWE_REC_BITS)) & 1) {
      setbit(out, i);
    }
  }
}

// <.>_2
void lwe_crossround2_ct(unsigned char *out, const uint32_t *in) {
  int i;
  memset((unsigned char *)out, 0, LWE_KEY_LENGTH >> 3);
  for (i = 0; i < LWE_KEY_LENGTH; i++) {
      uint32_t b;
      b = (in[i] >> (31 - LWE_REC_BITS)) & 1;
      out[(i) / 8] |= (((unsigned char) b) << (unsigned char) (i % 8));
      /*
    binary_printf(in[i], 32);
    printf(" -> ");
    binary_printf(out[i / 64], 64);
    printf(" <- ");
    binary_printf((in[i] >> (31 - LWE_REC_BITS)) & 1, 1);
    printf(" offset %i", (i % 64));
    printf("\n");
      */
  }
}

void lwe_rec(unsigned char *out, const uint32_t *w, const unsigned char *b) {
  lwe_rec_ct(out, w, b);
}

void lwe_rec_ct(unsigned char *out, const uint32_t *w, const unsigned char *b) {
  /*
  int i;
  memset((unsigned char *)out, 0, 16);
  for (i = 0; i < 128; i++) {
    uint32_t coswi;
    uint32_t B;
    coswi = w[i];
    B = ((getbit(b, i) == 0 && coswi >= (uint32_t) 1610612736 && coswi < (uint32_t) 3758096384) || (getbit(b, i) == 1 && (coswi >= (uint32_t) 2684354560 || coswi < (uint32_t) 536870912)));
    out[i / 64] |= (((uint64_t) B) << (uint64_t) (i % 64));
  }
  */
  int i, j, index = 0;

  // out should have enough space for 128-bits
  // TODO: restore constant time
  memset((unsigned char *)out, 0, LWE_KEY_LENGTH >> 3);
  uint32_t E = 1 << (30 - LWE_REC_BITS); // q / 2^{2 + LWE_REC_BITS}
  for (i = 0; i < LWE_KEY_LENGTH; i++) {
    uint32_t coswi = w[i];
    if (getbit(b, i) == 1) {
      coswi += (-E);
    } else {
      coswi += E;
    }
    // set the next LWE_REC_BITS of out to be equal to LWE_REC_BITS most significant bits of coswi
    for (j = 0; j < LWE_REC_BITS; j++) {
      uint32_t b = ((coswi >> (32 - LWE_REC_BITS + j)) & 1);
      out[index / 8] |= (((unsigned char) b) << (unsigned char) (index % 8));
      index++;
      if (index >= LWE_KEY_LENGTH) {
	return;
      }
    }
    /*
    if (i < 5) {
      binary_printf(coswi, 32);
      printf(" -> ");
      binary_printf(out[0], 64);
      printf(" <- ");
      binary_printf(coswi >> (32 - LWE_REC_BITS), LWE_REC_BITS);
      printf("\n");
    }
    */
  }
}

// multiply by s on the right
void lwe_key_gen_server(uint32_t *out, const uint32_t *a, const uint32_t *s, const uint32_t *e) {
  // a (1024 x 1024)
  // s,e (1024 x 12)
  // out = as + e (1024 x 12)
  size_t i, j, k, index = 0;
  
  // Make a temporary copy of s in the column-major order 
  uint32_t s_transpose[LWE_N_HAT][LWE_N];
  
  for (j = 0; j < LWE_N; j++)
    for (k = 0; k < LWE_N_HAT; k++)
      s_transpose[k][j] = s[j * LWE_N_HAT + k];
  
  for (i = 0; i < LWE_N; i++) {    
    for (k = 0; k < LWE_N_HAT; k++) {     
      uint32_t sum = e[index];
      for (j = 0; j < LWE_N; j++)
        sum += a[i * LWE_N + j] * s_transpose[k][j];
        
      out[index] = sum;
      index++;
    }
  }
}

// multiply by s on the left
void lwe_key_gen_client(uint32_t *out, const uint32_t *a_transpose, const uint32_t *s, const uint32_t *e) {
  // a (1024 x 1024)
  // s',e' (12 x 1024)
  // out = s'a + e' (12 x 1024)
  int i, j, k, index = 0;
  for (k = 0; k < LWE_N_HAT; k++) {
    for (i = 0; i < LWE_N; i++) {
      uint32_t sum = e[index];

      for (j = 0; j < LWE_N; j++)
	      sum += s[k * LWE_N + j] * a_transpose[i * LWE_N + j];
      
      out[index] = sum;
      
      index++;
    }
  }
}

// multiply by s on the left
void lwe_key_derive_client(uint32_t *out, const uint32_t *b, const uint32_t *s, const uint32_t *e) {
  // b (1024 x 12)
  // s (12 x 1024)
  // e (12 x 12)
  // out = sb + e
  int i, j, k;
  for (k = 0; k < LWE_N_HAT; k++) {
    for (i = 0; i < LWE_N_HAT; i++) {
      out[k * LWE_N_HAT + i] = e[k * LWE_N_HAT + i];
      for (j = 0; j < LWE_N; j++) {
	out[k * LWE_N_HAT + i] += s[k * LWE_N + j] * b[j * LWE_N_HAT + i];
      }
    }
  }
}
