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

/* crypto/lwekex/lwe_noise.h */
#ifndef HEADER_LWE_NOISE_H
#define HEADER_LWE_NOISE_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_LWEKEX
#error LWEKEX is disabled.
#endif

#include <stdint.h>

// Choice of how strict is the requirement of constant time:
//   0: no constraints
//   1: run time is constant except for table access patterns that are not,
//      may be vulnerable to cache-timing attacks
//   2: run time is constant, and table access patterns are fixed too
#define LWE_SAMPLE_CONST_TIME_LEVEL 2

// Choice of noise generation routine
// #define LWE_SAMPLE_N lwe_sample_n_table  // table-based method

//#define LWE_SAMPLE_N lwe_sample_n_binomial24 // samples from the binomial
// #define LWE_SAMPLE_N lwe_sample_n_binomial32 // samples from the binomial

#define LWE_SAMPLE_N lwe_sample_n_alias  // applies the alias method

// Choice of the tables for the alias method (used when
// LWE_SAMPLE_CONST_TIME_LEVEL == 0 or 1)
#define LWE_ALIAS_METHOD_THRESHOLDS ALIAS_METHOD_THRESHOLDS_S6
#define LWE_ALIAS_METHOD_ALIASES ALIAS_METHOD_ALIASES_S6

// Choice of the tables for the table method (used when
// LWE_SAMPLE_CONST_TIME_LEVEL == 2), also used as the reference CDF by
// lwekextest.
#define LWE_CDF_TABLE CDF_S6
#define LWE_CDF_TABLE_LENGTH CDF_LENGTH_S6

extern const uint16_t LWE_CDF_TABLE[];
extern const size_t LWE_CDF_TABLE_LENGTH;

void lwe_sample_n_table(uint32_t *s, const size_t n);
void lwe_sample_n_alias(uint32_t *s, const size_t n);

#endif
