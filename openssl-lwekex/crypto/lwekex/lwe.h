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
#ifndef HEADER_LWE_H_
#define HEADER_LWE_H_

#include <stdint.h>

#define LWE_REC_BITS 16
#define LWE_N \
  1024  // should be divisible by 64, otherwise need to fix sampling functions
#define LWE_N_HAT \
  3  // for a start we assume LWE_M_HAT = LWE_N_HAT, LWE_N_HAT * LWE_N_HAT
     // should be divisable by 8
#define LWE_KEY_LENGTH \
  128  // the length of the resulting key (TODO: make 256), should be
       // LWE_KEY_LENGTH <= LWE_N_HAT * LWE_N_HAT, need to be a multiple of 8

// seems that nothing restricts the form of the modulus q, so we can stick to
// 2^32
// which would simply mean that we will be using unsigned 32-bits integer

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
// where a (1024 x 1024), s,e (1024 x 12),
void lwe_key_gen_server(uint32_t *out, const uint32_t *a, const uint32_t *s,
                        const uint32_t *e);
// multiply by s on the left
// computes out = sa + e
// where a (1024 x 1024), s,e (12 x 1024),
void lwe_key_gen_client(uint32_t *out, const uint32_t *a_transpose,
                        const uint32_t *s, const uint32_t *e);
// multiply by s on the left
// computes out = sb+e
// where b (1024 x 12), s (12 x 1024), e (12 x 12)
void lwe_key_derive_client(uint32_t *out, const uint32_t *b, const uint32_t *s,
                           const uint32_t *e);

#endif /* _LWE_H_ */
