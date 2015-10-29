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
#ifndef HEADER_LWE_H_
#define HEADER_LWE_H_

#include <stdint.h>

// #define DEBUG_LOGS

#define LWE_REC_BITS 20  // Number of bits extracted from a ring element.

#define LWE_N \
  1024  // Dimensionality of the lattice. Should be divisible by 64, otherwise
        // need to fix sampling functions.
#define LWE_N_BAR \
  3  // Number of vectors chosen by each of the parties. (The protocol is
     // currenrly symmetric, LWE_M_HAT = LWE_N_HAT.) LWE_N_HAT * LWE_N_HAT
     // should be divisible by 8
#define LWE_KEY_LENGTH \
  128  // The length of the resulting key in bits (TODO: make 256). Should be a
       // multiple of 8 and satisfy LWE_KEY_LENGTH <= LWE_N_HAT * LWE_N_HAT *
       // LWE_REC_BITS

#define LWE_KEY_TRUNCATE 0  // The number of least significant bits that can be
                            // truncated (or just be zeroed out).

#define LWE_REC_LENGTH (((LWE_N_BAR * LWE_N_BAR + 7) / 8))

// It seems that nothing restricts the form of the modulus q, so we can stick to
// 2^32, which means that we are using unsigned 32-bit integer.

void lwe_sample_ct(uint32_t *s);
void lwe_sample(uint32_t *s);
void lwe_sample_n_ct(uint32_t *s, int n);
void lwe_sample_n(uint32_t *s, int n);

void lwe_round2_ct(unsigned char *out, const uint32_t *in);
void lwe_round2(unsigned char *out, uint32_t *in);

void lwe_crossround2_ct(unsigned char *out, const uint32_t *in);
void lwe_crossround2(unsigned char *out, const uint32_t *in);

void lwe_rec_ct(unsigned char *out, uint32_t *w, const unsigned char *b);
void lwe_rec(unsigned char *out, uint32_t *w, const unsigned char *b);

// multiply by s on the right
// computes out = as + e
// where a (1024 x 1024), s,e (1024 x 3),
int lwe_key_gen_server(uint32_t *out, const uint32_t *a, const uint32_t *s,
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
void lwe_key_round(uint32_t *vec, const size_t length, const int b);

void lwe_pack(unsigned char *out, const size_t outlen, const uint32_t *in,
              const size_t inlen, const unsigned char msb);

void lwe_key_round_directed(uint32_t *vec, const size_t length, const int b,
                            const unsigned char *dir);

#endif /* _LWE_H_ */
