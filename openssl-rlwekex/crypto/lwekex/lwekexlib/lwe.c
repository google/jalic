#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "lwe.h"

#include "lwe_table.h"

#define setbit(a,x) ((a)[(x)/64] |= (((uint64_t) 1) << (uint64_t) ((x)%64)))
#define getbit(a,x) (((a)[(x)/64] >> (uint64_t) ((x)%64)) & 1)
#define clearbit(a,x) ((a)[(x)/64] &= ((~((uint64_t) 0)) - (((uint64_t) 1) << (uint64_t) ((x)%64))))

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
  int i, j, k, index;
  for (k = 0; k < 12; k++) {
    for (i = 0; i < 16; i++) {
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
	index = (k * 16 + i) * 64 + j;
	s[index] = single_sample_ct(rnd);
	// printf("    * %i: 0x%08X\n", index, s[index]);
	t = 0xFFFFFFFF - s[index];
	s[index] = ((t & (uint32_t) m) | (s[index] & (~((uint32_t) m))));
      }
    }
  }
}

void lwe_sample_n(uint32_t *s, int n) {
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
      RANDOM192(rnd);
      m = (r & 1);
      r >>= 1;
      m = 2 * m - 1;
      s[index] = single_sample(rnd);
      if (m == -1) {
	s[index] = 0xFFFFFFFF - s[index];
      }
    }
  }
}

// s (12 x 1024)
void lwe_sample(uint32_t *s) {
  RANDOM_VARS;
  int i, j, k, index;
  for (k = 0; k < 12; k++) {
    for (i = 0; i < 16; i++) {
      uint64_t r = RANDOM64;
      for (j = 0; j < 64; j++) {
	index = (k * 16 + i) * 64 + j;
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
      }
    }
  }
}

// [.]_2
void lwe_round2(uint64_t *out, const uint32_t *in) {
  int i, j, index;

  // out should have enough space for 128-bits //NB!
  memset((unsigned char *)out, 0, 16);

  //1 iff between q/4 and 3*q/4
  // extracting 128 bits from a 12 by 12 32-bits matrix, the number of elements in *in should be 144
  for (i = 0; i < 128; i++) {
    // if (in[i] >= 1073741824 && in[i] <= 3221225471) { // from rlwe
    // if (((in[i] >> 30) & 1) + ((in[i] >> 31) & 1) == 1) { // previous mechanism
    for (j = 0; j < LWE_REC_BITS; j++) {
      index = i * LWE_REC_BITS + j;
      if (index > 128) {
	return;
      }
      if ((in[i] >> (32 - LWE_REC_BITS + j)) & 1) { // previous mechanism
	setbit(out, index);
      }
    }
  }
}

// #define DEBUG_LOGS
void binary_printf(uint64_t n, int bits_num) {
 #ifdef DEBUG_LOGS
  int i = 0;
  while (n) {
    if (n & 1) printf("1");
    else printf("0");
    n >>= 1;
    i++;
  }
  for (; i < bits_num; i++) {
    printf("0");
  }
#endif /* DEBUG_LOGS */
}

/* Constant time version. */
// [.]_2
void lwe_round2_ct(uint64_t *out, const uint32_t *in) {
  int i, j, index;
  // out should have enough space for 128-bits //NB!
  memset((unsigned char *)out, 0, 16);
  // extracting 128 bits from a 12 by 12 32-bits matrix, the number of elements should be 144
  for (i = 0; i < 128; i++) {
    // uint32_t b = (((in[i] >> 30) & 1) + ((in[i] >> 31) & 1)) & 1;
    for (j = 0; j < LWE_REC_BITS; j++) {
      index = i * LWE_REC_BITS + j;
      if (index > 128) {
	return;
      }
      uint32_t b = ((in[i] >> (32 - LWE_REC_BITS + j)) & 1);
      out[index / 64] |= (((uint64_t) b) << (uint64_t) (index % 64));
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
void lwe_crossround2(uint64_t *out, const uint32_t *in) {
  int i;
  // out should have enough space for 1024-bits
  memset((unsigned char *)out, 0, 16);

  // in (12 x 12)
  // take first 128 elements of in and convert them to bits
  for (i = 0; i < 128; i++) {
    //q/4 to q/2 and q/2 to q
    if ((in[i] >> (31 - LWE_REC_BITS)) & 1) {
      setbit(out, i);
    }
  }
}

// <.>_2
void lwe_crossround2_ct(uint64_t *out, const uint32_t *in) {
  int i;
  memset((unsigned char *)out, 0, 16);
  for (i = 0; i < 128; i++) {
      uint32_t b;
      b = (in[i] >> (31 - LWE_REC_BITS)) & 1;
      out[(i) / 64] |= (((uint64_t) b) << (uint64_t) (i % 64));
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

void lwe_rec(uint64_t *out, const uint32_t *w, const uint64_t *b) {
  lwe_rec_ct(out, w, b);
}

void lwe_rec_ct(uint64_t *out, const uint32_t *w, const uint64_t *b) {
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
  int i, j, index;

  // out should have enough space for 128-bits
  // TODO: restore constant time
  memset((unsigned char *)out, 0, 16);
  uint32_t E = 1 << (30 - LWE_REC_BITS); // q / 2^{2 + LWE_REC_BITS}
  for (i = 0; i < 128; i++) {
    uint32_t coswi = w[i];
    if (getbit(b, i) == 1) {
      coswi += (-E);
    } else {
      coswi += E;
    }
    // set the next LWE_REC_BITS of out to be equal to LWE_REC_BITS most significant bits of coswi
    for (j = 0; j < LWE_REC_BITS; j++) {
      index = i * LWE_REC_BITS + j;
      if (index > 128) {
	return;
      }
      uint32_t b = ((coswi >> (32 - LWE_REC_BITS + j)) & 1);
      out[index / 64] |= (((uint64_t) b) << (uint64_t) (index % 64));
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
  // might want to optimize for array accesses - change the multiplication by 12 in the indices by switching to transposes
  // a (1024 x 1024)
  // s,e (1024 x 12)
  // out = as + e (1024 x 12)
  int i, j, k, index;
  for (i = 0; i < 1024; i++) {
    for (k = 0; k < 12; k++) {
      index = i * 12 + k;
      out[index] = e[index];
      for (j = 0; j < 1024; j++) {
	out[index] += a[(i << 10) + j] * s[j * 12 + k];
      }
    }
  }
}

// multiply by s on the left
void lwe_key_gen_client(uint32_t *out, const uint32_t *a_transpose, const uint32_t *s, const uint32_t *e) {
  // a (1024 x 1024)
  // s',e' (12 x 1024)
  // out = s'a + e' (12 x 1024)
  int i, j, k, index;
  for (k = 0; k < 12; k++) {
    for (i = 0; i < 1024; i++) {
      index = (k << 10) + i;
      out[index] = e[index];
      for (j = 0; j < 1024; j++) {
	// out[index] += s[(k << 10) + j] * a[(j << 10) + i];
	out[index] += s[(k << 10) + j] * a_transpose[(i << 10) + j];
      }
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
  for (k = 0; k < 12; k++) {
    for (i = 0; i < 12; i++) {
      out[k * 12 + i] = e[k * 12 + i];
      for (j = 0; j < 1024; j++) {
	out[k * 12 + i] += s[k * 1024 + j] * b[j * 12 + i];
      }
    }
  }
}
