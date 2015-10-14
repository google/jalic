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

/* crypto/lwekex/lwekex.h */
#ifndef HEADER_LWEKEX_H
#define HEADER_LWEKEX_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_LWEKEX
#error LWEKEX is disabled.
#endif

#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lwe_param_st LWE_PARAM;
typedef struct lwe_pub_st LWE_PUB;
typedef struct lwe_pair_st LWE_PAIR;
typedef struct lwe_rec_st LWE_REC;
typedef struct lwe_ctx_st LWE_CTX;

/* Allocate and deallocate parameters, public keys, private key / public key
 * pairs, and reconciliation data structures */
LWE_PARAM *LWE_PARAM_new(void);
void LWE_PARAM_free(LWE_PARAM *param);

LWE_PUB *LWE_PUB_new(void);
LWE_PUB *LWE_PUB_copy(LWE_PUB *dest, const LWE_PUB *src);
void LWE_PUB_free(LWE_PUB *pub);

LWE_PAIR *LWE_PAIR_new(void);
LWE_PAIR *LWE_PAIR_copy(LWE_PAIR *dest, const LWE_PAIR *src);
LWE_PAIR *LWE_PAIR_dup(const LWE_PAIR *pair);
void LWE_PAIR_free(LWE_PAIR *pair);

LWE_REC *LWE_REC_new(void);
void LWE_REC_free(LWE_REC *rec);

LWE_CTX *LWE_CTX_new(void);
void LWE_CTX_free(LWE_CTX *ctx);

/* Generate key pair */
int LWE_PAIR_generate_key(LWE_PAIR *key, LWE_CTX *ctx, char isForServer);

/* Convert public keys and reconciliation data structures from/to binary */
LWE_PUB *o2i_LWE_PUB(LWE_PUB **pub, const unsigned char *in, long len);
int i2o_LWE_PUB(LWE_PUB *pub, unsigned char **out);
LWE_REC *o2i_LWE_REC(LWE_REC **rec, const unsigned char *in, long len);
int i2o_LWE_REC(LWE_REC *rec, unsigned char **out);

/* Get public key from a key pair */
LWE_PUB *LWE_PAIR_get_publickey(LWE_PAIR *pair);
/* Does private key exist? */
int LWE_PAIR_has_privatekey(LWE_PAIR *pair);

/* Compute shared secret values */
int LWEKEX_compute_key_alice(
    void *out, size_t outlen, const LWE_PUB *peer_pub_key,
    const LWE_REC *peer_reconciliation, const LWE_PAIR *priv_pub_key,
    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen),
    LWE_CTX *ctx, uint32_t *w);
int LWEKEX_compute_key_bob(void *out, size_t outlen, LWE_REC *reconciliation,
                           const LWE_PUB *peer_pub_key,
                           const LWE_PAIR *priv_pub_key,
                           void *(*KDF)(const void *in, size_t inlen, void *out,
                                        size_t *outlen),
                           LWE_CTX *ctx, uint32_t *v);

void print_first_element_REC(const LWE_REC *rec);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_LWEKEX_strings(void);

/* Error codes for the LWEKEX functions. */

/* Function codes. */
#define LWEKEX_F_I2O_LWE_PUB				 100
#define LWEKEX_F_I2O_LWE_REC				 104
#define LWEKEX_F_LWEKEX_				 107
#define LWEKEX_F_LWEKEX_COMPUTE_KEY_ALICE		 108
#define LWEKEX_F_LWEKEX_COMPUTE_KEY_BOB			 109
#define LWEKEX_F_LWE_CTX_NEW				 114
#define LWEKEX_F_LWE_PAIR_COPY				 115
#define LWEKEX_F_LWE_PAIR_NEW				 102
#define LWEKEX_F_LWE_PARAM_NEW				 113
#define LWEKEX_F_LWE_PUB_COPY				 116
#define LWEKEX_F_LWE_PUB_NEW				 103
#define LWEKEX_F_LWE_REC_NEW				 106
#define LWEKEX_F_O2I_LWE_PUB				 101
#define LWEKEX_F_O2I_LWE_REC				 105
#define LWEKEX_F_RANDOM32				 111
#define LWEKEX_F_RANDOM64				 112
#define LWEKEX_F_RANDOM8				 110
#define LWEKEX_F_RANDOMBUFF      117
#define LWEKEX_F_RANDOM_VARS     118

/* Reason codes. */
#define LWEKEX_R_INVALID_LENGTH				 102
#define LWEKEX_R_KDF_FAILED				 100
#define LWEKEX_R_RANDOM_FAILED				 101

#ifdef  __cplusplus
}
#endif
#endif
