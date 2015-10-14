/*
Copyright 2015 Google Inc. All Rights Reserved.

Author: nikolaenko@google.com (Valeria Nikolaenko)
Author: pseudorandom@google.com (Ananth Raghunathan)
Author: mironov@google.com (Ilya Mironov)
*/

#ifndef HEADER_LWE_H_
#define HEADER_LWE_H_

#include <stdint.h>

#define LWE_REC_BITS 20
#define LWE_N \
  1024  // Dimensionality of the lattice. Should be divisible by 64, otherwise
        // need to fix sampling functions.
#define LWE_N_HAT \
  3  // Number of vectors chosen by each of the parties. (The protocol is
     // currenrly symmetric, LWE_M_HAT = LWE_N_HAT.) LWE_N_HAT * LWE_N_HAT
     // should be divisible by 8
#define LWE_KEY_LENGTH \
  128  // The length of the resulting key in bits (TODO: make 256). Should be a
       // multiple of 8 and satisfy LWE_KEY_LENGTH <= LWE_N_HAT * LWE_N_HAT *
       // LWE_REC_BITS

// It seems that nothing restricts the form of the modulus q, so we can stick to
// 2^32, which means that we are using unsigned 32-bit integer.

void lwe_sample_ct(uint32_t *s);
void lwe_sample(uint32_t *s);
void lwe_sample_n_ct(uint32_t *s, int n);
void lwe_sample_n(uint32_t *s, int n);

void lwe_round2_ct(unsigned char *out, const uint32_t *in);
void lwe_round2(unsigned char *out, const uint32_t *in);

void lwe_crossround2_ct(unsigned char *out, const uint32_t *in);
void lwe_crossround2(unsigned char *out, const uint32_t *in);

void lwe_rec_ct(unsigned char *out, const uint32_t *w, const unsigned char *b);
void lwe_rec(unsigned char *out, const uint32_t *w, const unsigned char *b);

// multiply by s on the right
// computes out = as + e
// where a (1024 x 1024), s,e (1024 x 3),
void lwe_key_gen_server(uint32_t *out, const uint32_t *a, const uint32_t *s,
                        const uint32_t *e);
// multiply by s on the left
// computes out = sa + e
// where a (1024 x 1024), s,e (3 x 1024),
void lwe_key_gen_client(uint32_t *out, const uint32_t *a_transpose,
                        const uint32_t *s, const uint32_t *e);
// multiply by s on the left
// computes out = sb+e
// where b (1024 x 3), s (3 x 1024), e (3 x 3)
void lwe_key_derive_client(uint32_t *out, const uint32_t *b, const uint32_t *s,
                           const uint32_t *e);

// round the entire vector to the nearest multiple of 2^b
void lwe_key_round(uint32_t *vec, const int length, const int b);

#endif /* _LWE_H_ */
