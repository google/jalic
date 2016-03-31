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

#define LWE_DIV_ROUNDUP(x, y) (((x) + (y) - 1) / y)

//#define LWE_Q 4294967296 // implicitly use Q == 2**32

#define LWE_EXTRACTED_BITS 15 // Number of bits extracted from a ring element.

#define LWE_N \
  1024  // Dimensionality of the lattice. Should be divisible by 64, otherwise
        // need to fix sampling functions.

#define LWE_N_BAR \
  3  // Number of vectors chosen by each of the parties. (The protocol is
     // currently symmetric, LWE_M_HAT = LWE_N_HAT.)

#define LWE_KEY_BITS \
  128  // The length of the resulting key in bits. Should be a
       // multiple of 8 and satisfy LWE_KEY_BITS <= LWE_N_HAT * LWE_N_HAT *
       // LWE_EXTRACTED_BITS

#define LWE_TRUNCATED_BITS \
  6  // The number of least significant bits that are truncated

#define LWE_PUB_LENGTH \
  LWE_DIV_ROUNDUP(LWE_N_BAR * LWE_N * (32 - LWE_TRUNCATED_BITS), 8)
// Length (in bytes) of the vectors exchanged by parties

#define LWE_REC_HINT_LENGTH LWE_DIV_ROUNDUP(LWE_N_BAR * LWE_N_BAR, 8)
// Length (in bytes) of the reconciliation hint vector

void lwe_round2_ct(unsigned char *out, uint32_t *in);
void lwe_round2(unsigned char *out, uint32_t *in);

void lwe_crossround2_ct(unsigned char *out, const uint32_t *in);
void lwe_crossround2(unsigned char *out, const uint32_t *in);

void lwe_reconcile_ct(unsigned char *out, uint32_t *w, const unsigned char *hint);
void lwe_reconcile(unsigned char *out, uint32_t *w, const unsigned char *hint);

// multiply by s on the right
// computes out = as + e
// where a (N x N), s,e (N x N_BAR),
int lwe_key_gen_server(unsigned char *out, const uint32_t *a, const uint32_t *s,
                       const uint32_t *e);

// multiply by s on the left
// computes out = sa + e
// where a (N x N), s,e (N_BAR x N),
int lwe_key_gen_client(unsigned char *out, const uint32_t *a_transpose,
                        const uint32_t *s, const uint32_t *e);

// multiply by s on the left
// computes out = sb + e
// where b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
void lwe_key_derive_client(uint32_t *out, const uint32_t *b, const uint32_t *s,
                           const uint32_t *e);

// round the entire vector to the nearest multiple of 2^b
void lwe_key_round(uint32_t *vec, const size_t length, const int b);

// round the entire vector to the nearest multiple of 2^b, using the hint vector
// for direction of rounding where necessary
void lwe_key_round_hints(uint32_t *vec, const size_t length, const int b,
                            const unsigned char *hint);

void lwe_pack(unsigned char *out, const size_t outlen, const uint32_t *in,
              const size_t inlen, const unsigned char msb);

void lwe_unpack(uint32_t *out, const size_t outlen, const unsigned char *in,
              const size_t inlen, const unsigned char msb);

int lwe_add_unif_noise(uint32_t *b, const size_t blen, const unsigned char lsb);

#endif /* _LWE_H_ */
