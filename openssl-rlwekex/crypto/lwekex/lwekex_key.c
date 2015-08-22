/* crypto/lwekex/lwekex_key.c */

#include <string.h>
#include <openssl/rand.h>
#include "lwekex_locl.h"

#define RANDOMNESS_AESCTR

#ifdef RANDOMNESS_AESCTR
#include <openssl/aes.h>
#define RANDOM_VARS \
	AES_KEY aes_key; \
	unsigned char aes_key_bytes[16]; \
	RAND_bytes(aes_key_bytes, 16); \
	AES_set_encrypt_key(aes_key_bytes, 128, &aes_key); \
	unsigned char aes_ivec[AES_BLOCK_SIZE]; \
	memset(aes_ivec, 0, AES_BLOCK_SIZE); \
	unsigned char aes_ecount_buf[AES_BLOCK_SIZE]; \
	memset(aes_ecount_buf, 0, AES_BLOCK_SIZE); \
	unsigned int aes_num = 0; \
	unsigned char aes_in[AES_BLOCK_SIZE]; \
	memset(aes_in, 0, AES_BLOCK_SIZE);
#define RANDOM8   ((uint8_t) lwe_randomplease(&aes_key, aes_ivec, aes_ecount_buf, &aes_num, aes_in))
#define RANDOM32 ((uint32_t) lwe_randomplease(&aes_key, aes_ivec, aes_ecount_buf, &aes_num, aes_in))
#define RANDOM64 ((uint64_t) lwe_randomplease(&aes_key, aes_ivec, aes_ecount_buf, &aes_num, aes_in))

uint64_t lwe_randomplease(AES_KEY *aes_key, unsigned char aes_ivec[AES_BLOCK_SIZE],
                      unsigned char aes_ecount_buf[AES_BLOCK_SIZE],
                      unsigned int *aes_num, unsigned char aes_in[AES_BLOCK_SIZE]) {
	uint64_t out;
	AES_ctr128_encrypt(aes_in, (unsigned char *) &out, 8, aes_key, aes_ivec, aes_ecount_buf, aes_num);
	return out;
}
#endif
/*
#ifdef RANDOMNESS_RCFOUR
#include <openssl/rc4.h>
#define RANDOM_VARS \
	RC4_KEY rc4_key; \
	unsigned char rc4_key_bytes[16]; \
	RAND_bytes(rc4_key_bytes, 16); \
	RC4_set_key(&rc4_key, 16, rc4_key_bytes);

#define RANDOM8   ((uint8_t) randomplease(&rc4_key))
#define RANDOM32 ((uint32_t) randomplease(&rc4_key))
#define RANDOM64 ((uint64_t) randomplease(&rc4_key))

uint64_t randomplease(RC4_KEY *rc4_key) {
	uint64_t b;
	uint64_t z = (uint64_t) 0;
	RC4(rc4_key, 8, (unsigned char *) &z, (unsigned char *) &b);
	return b;
}

#endif

#ifdef RANDOMNESS_RAND_bytes
#define RANDOM_VARS
#define RANDOM8 (random8())
#define RANDOM32 (random32())
#define RANDOM64 (random64())

uint8_t random8() {
	uint8_t b;
	int r = RAND_bytes((unsigned char *) &b, 1);
	if (r != 1) {
		RLWEKEXerr(RLWEKEX_F_RANDOM8, RLWEKEX_R_RANDOM_FAILED);
	}
	return b;
}
uint32_t random32() {
	uint32_t b;
	int r = RAND_bytes((unsigned char *) &b, 4);
	if (r != 1) {
		RLWEKEXerr(RLWEKEX_F_RANDOM32, RLWEKEX_R_RANDOM_FAILED);
	}
	return b;
}
uint64_t random64() {
	uint64_t b;
	int r = RAND_bytes((unsigned char *) &b, 8);
	if (r != 1) {
		RLWEKEXerr(RLWEKEX_F_RANDOM64, RLWEKEX_R_RANDOM_FAILED);
	}
	return b;
}
#endif
*/
#include "lwekexlib/lwe.c"
#include "lwekexlib/lwe_a.h"

// #define DEBUG_LOGS

int debug_printf(const char *format, ...) {
 #ifdef DEBUG_LOGS
	va_list args;
	int ret;
	va_start(args, format);
	ret = vprintf(format, args);
	va_end(args);
	return ret;
#else
	return 0;
#endif /* DEBUG_LOGS */
}

/* Allocate and deallocate auxiliary variables (context) data structure */

LWE_CTX *LWE_CTX_new(void) {
	LWE_CTX *ret;
	ret = (LWE_CTX *)OPENSSL_malloc(sizeof(LWE_CTX));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_CTX_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	return (ret);
  err:
  	OPENSSL_free(ret);
  	return (NULL);
}

void LWE_CTX_free(LWE_CTX *r) {
	if (r == NULL) return;
	OPENSSL_cleanse((void *)r, sizeof(LWE_CTX));
	OPENSSL_free(r);
}

/* Allocate and deallocate public parameters data structure */

LWE_PARAM *LWE_PARAM_new(void) {
	LWE_PARAM *ret;

	ret = (LWE_PARAM *)OPENSSL_malloc(sizeof(LWE_PARAM));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PARAM_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->version = 1;
	ret->flags = 0;
	ret->references = 1;

	ret->a = (uint32_t *) lwe_a;
	ret->a_transpose = (uint32_t *) lwe_a_transpose;

	return (ret);
}

void LWE_PARAM_free(LWE_PARAM *r) {
	int i;

	if (r == NULL) return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("LWE_PARAM", r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0) {
		fprintf(stderr, "LWE_PARAM_free, bad reference count\n");
		abort();
	}
#endif

	OPENSSL_cleanse((void *)r, sizeof(LWE_PARAM));

	OPENSSL_free(r);
}

/* Allocate and deallocate public key data structure */

LWE_PUB *LWE_PUB_new(void) {
	LWE_PUB *ret;

	ret = (LWE_PUB *)OPENSSL_malloc(sizeof(LWE_PUB));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PUB_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->version = 1;
	ret->flags = 0;
	ret->references = 1;

	ret->param = NULL;
	ret->b = (uint32_t *) OPENSSL_malloc (1024 * 12 * sizeof (uint32_t));

	return (ret);
}

LWE_PUB *LWE_PUB_copy(LWE_PUB *dest, const LWE_PUB *src) {
	if (dest == NULL || src == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PUB_COPY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	/* copy the parameters; this takes advantage of the fact that we only currently
	   support one set of parameters */
	if (!dest->param) {
		dest->param = LWE_PARAM_new();
	}

	/* copy the public key */
	if (src->b) {
		if (!dest->b) {
			dest->b = OPENSSL_malloc(1024 * 12 * sizeof (uint32_t));
		}
		memcpy(dest->b, src->b, 1024 * 12 * sizeof (uint32_t));
	}

	/* copy the rest */
	dest->version   = src->version;
	dest->flags = src->flags;

	return dest;
}

void LWE_PUB_free(LWE_PUB *r) {
	int i;

	if (r == NULL) return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("LWE_PUB", r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0) {
		fprintf(stderr, "LWE_PUB_free, bad reference count\n");
		abort();
	}
#endif

	LWE_PARAM_free(r->param);

	OPENSSL_cleanse(r->b, 1024 * 12 * sizeof (uint32_t));
	OPENSSL_free(r->b);

	OPENSSL_cleanse((void *)r, sizeof(LWE_PUB));

	OPENSSL_free(r);
}

/* Allocate and deallocate public key / private key pair data structure */
LWE_PAIR *LWE_PAIR_new(void) {
	LWE_PAIR *ret;

	ret = (LWE_PAIR *)OPENSSL_malloc(sizeof(LWE_PAIR));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PAIR_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->version = 1;
	ret->flags = 0;
	ret->references = 1;

	ret->pub = NULL;

	ret->s = (uint32_t *) OPENSSL_malloc (1024 * 12 * sizeof (uint32_t));
	ret->e = (uint32_t *) OPENSSL_malloc (1024 * 12 * sizeof (uint32_t));

	return (ret);
}

LWE_PAIR *LWE_PAIR_copy(LWE_PAIR *dest, const LWE_PAIR *src) {
	if (dest == NULL || src == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PAIR_COPY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	/* copy the public key */
	if (src->pub) {
		if (dest->pub)
			LWE_PUB_free(dest->pub);
		dest->pub = LWE_PUB_new();
		if (dest->pub == NULL)
			return NULL;
		if (!LWE_PUB_copy(dest->pub, src->pub))
			return NULL;
	}

	/* copy the private key */
	if (src->s) {
		if (!dest->s) {
			dest->s = OPENSSL_malloc(1024 * 12 * sizeof (uint32_t));
		}
		memcpy(dest->s, src->s, 1024 * 12 * sizeof (uint32_t));
	}
	if (src->e) {
		if (!dest->e) {
			dest->e = OPENSSL_malloc(1024 * 12 * sizeof (uint32_t));
		}
		memcpy(dest->e, src->e, 1024 * 12 * sizeof (uint32_t));
	}

	/* copy the rest */
	dest->version   = src->version;
	dest->flags = src->flags;

	return dest;
}

LWE_PAIR *LWE_PAIR_dup(const LWE_PAIR *pair) {
	LWE_PAIR *ret = LWE_PAIR_new();
	if (ret == NULL)
		return NULL;
	if (LWE_PAIR_copy(ret, pair) == NULL) {
		LWE_PAIR_free(ret);
		return NULL;
	}
	return ret;
}

void LWE_PAIR_free(LWE_PAIR *r) {
	int i;

	if (r == NULL) return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("LWE_PAIR", r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0) {
		fprintf(stderr, "LWE_PAIR_free, bad reference count\n");
		abort();
	}
#endif

	LWE_PUB_free(r->pub);

	OPENSSL_cleanse(r->s, 1024 * 12 * sizeof (uint32_t));
	OPENSSL_free(r->s);
	OPENSSL_cleanse(r->e, 1024 * 12 * sizeof (uint32_t));
	OPENSSL_free(r->e);

	OPENSSL_cleanse((void *)r, sizeof(LWE_PAIR));

	OPENSSL_free(r);
}

/* Allocate and deallocate reconciliation data structure */
LWE_REC *LWE_REC_new(void) {
	LWE_REC *ret;

	ret = (LWE_REC *)OPENSSL_malloc(sizeof(LWE_REC));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_REC_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->version = 1;
	ret->flags = 0;
	ret->references = 1;

	ret->c = (uint64_t *) malloc (2 * sizeof (uint64_t));

	return (ret);
}

void LWE_REC_free(LWE_REC *r) {
	int i;

	if (r == NULL) return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("LWE_REC", r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0) {
		fprintf(stderr, "LWE_REC_free, bad reference count\n");
		abort();
	}
#endif

	OPENSSL_cleanse(r->c, 2 * sizeof (uint64_t));
	OPENSSL_free(r->c);

	OPENSSL_cleanse((void *)r, sizeof(LWE_REC));

	OPENSSL_free(r);
}

/* Generate key pair */
int LWE_PAIR_generate_key(LWE_PAIR *key, LWE_CTX *ctx, char isForServer) {
	int	ok = 0;

	key->pub = LWE_PUB_new();
	if (key->pub == NULL) {
		goto err;
	}

	key->pub->param = LWE_PARAM_new();
	if (key->pub->param == NULL) {
		goto err;
	}

#if CONSTANT_TIME
	lwe_sample_ct(key->s);
	lwe_sample_ct(key->e);
#else
	lwe_sample(key->s);
	lwe_sample(key->e);
#endif
	// find min/max S
	int32_t signed_s_min = key->s[0], signed_s_max = key->s[0];
	int i;
	for (i = 0; i < 1024 * 12 - 1; i++) {
	  if ((int32_t)key->s[i] < signed_s_min) {
	    signed_s_min = (int32_t)key->s[i];
	  }
	  if ((int32_t)key->s[i] > signed_s_max) {
	    signed_s_max = (int32_t)key->s[i];
	  }
	}
	debug_printf("  secret S in [%i, %i]\n", signed_s_min, signed_s_max);
	debug_printf("  secret S = ");
	debug_printf("0x%08X ", key->s[0]);
	debug_printf("0x%08X ", key->s[1]);
	debug_printf("...0x%08X\n", key->s[1024 * 12 - 1]);

	debug_printf("  secret E = ");
	debug_printf("0x%08X ", key->e[0]);
	debug_printf("0x%08X ", key->e[1]);
	debug_printf("...0x%08X\n", key->e[1024 * 12 - 1]);

	if (isForServer) {
          lwe_key_gen_server(key->pub->b, key->pub->param->a, key->s, key->e);
        }
	else {
          lwe_key_gen_client(key->pub->b, key->pub->param->a_transpose, key->s, key->e);
        }

	ok = 1;
	goto err;

err:
	return (ok);
}

/* Convert public keys data structures from/to binary */
LWE_PUB *o2i_LWE_PUB(LWE_PUB **pub, const unsigned char *in, long len) {
  int i;
  if (pub == NULL) {
    RLWEKEXerr(RLWEKEX_F_O2I_RLWE_PUB, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (*pub == NULL && (*pub = LWE_PUB_new()) == NULL) {
    RLWEKEXerr(RLWEKEX_F_O2I_RLWE_PUB, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  if (len != 1024 * 4 * 12) {
    RLWEKEXerr(RLWEKEX_F_O2I_RLWE_PUB, RLWEKEX_R_INVALID_LENGTH);
    return 0;
  }

  for (i = 0; i < 1024 * 12; i++) {
    (*pub)->b[i] = (((uint32_t) in[4 * i + 0]) << 24) |
      (((uint32_t) in[4 * i + 1]) << 16) |
      (((uint32_t) in[4 * i + 2]) << 8) |
      ( (uint32_t) in[4 * i + 3]);
  }

  return *pub;
}

int i2o_LWE_PUB(LWE_PUB *pub, unsigned char **out) {
	size_t buf_len = 0;
	int new_buffer = 0, i;

	if (pub == NULL) {
		RLWEKEXerr(RLWEKEX_F_I2O_RLWE_PUB, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	buf_len = 1024 * 4 * 12;

	if (out == NULL || buf_len == 0)
		/* out == NULL => just return the length of the octet string */
		return buf_len;

	if (*out == NULL) {
		if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
			RLWEKEXerr(RLWEKEX_F_I2O_RLWE_PUB, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		new_buffer = 1;
	}

	for (i = 0; i < 1024 * 12; i++) {
		(*out)[4 * i + 0] = (unsigned char)  (pub->b[i] >> 24);
		(*out)[4 * i + 1] = (unsigned char) ((pub->b[i] >> 16) & 0xff);
		(*out)[4 * i + 2] = (unsigned char) ((pub->b[i] >>  8) & 0xff);
		(*out)[4 * i + 3] = (unsigned char) ( pub->b[i]        & 0xff);
	}

	if (!new_buffer)
		*out += buf_len;
	return buf_len;
}

/* Convert reconciliation data structure from/to binary */

LWE_REC *o2i_LWE_REC(LWE_REC **rec, const unsigned char *in, long len) {

	if (rec == NULL) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_REC, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (*rec == NULL && (*rec = LWE_REC_new()) == NULL) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_REC, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	// 128 bits are embedded into 16 * 8-bits numbers
	if (len != 16) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_REC, RLWEKEX_R_INVALID_LENGTH);
		return 0;
	}
	memcpy((unsigned char *) ((*rec)->c), in, len);

	return *rec;
}

int i2o_LWE_REC(LWE_REC *rec, unsigned char **out) {
	size_t buf_len = 0;
	int new_buffer = 0;

	if (rec == NULL) {
		RLWEKEXerr(RLWEKEX_F_I2O_RLWE_REC, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	buf_len = 16;

	if (out == NULL || buf_len == 0)
		/* out == NULL => just return the length of the octet string */
		return buf_len;

	if (*out == NULL) {
		if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
			RLWEKEXerr(RLWEKEX_F_I2O_RLWE_REC, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		new_buffer = 1;
	}

	memcpy(*out, (unsigned char *) rec->c, buf_len);

	if (!new_buffer)
		*out += buf_len;
	return buf_len;
}

/* Get public key from a key pair */
LWE_PUB *LWE_PAIR_get_publickey(LWE_PAIR *pair) {
	if (pair == NULL) return NULL;
	return pair->pub;
}

/* Does private key exist? */
int LWE_PAIR_has_privatekey(LWE_PAIR *pair) {
	return (pair->s != NULL) && (pair->e != NULL);
}

/* Compute shared secret values */
int LWEKEX_compute_key_alice(void *out, size_t outlen, const LWE_PUB *peer_pub_key,  const LWE_REC *peer_reconciliation,
                              const LWE_PAIR *priv_pub_key, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen), LWE_CTX *ctx) {

	int ret = -1;

	uint32_t *w = (uint32_t *) OPENSSL_malloc (12 * 12 * sizeof (uint32_t));
	uint64_t *ka  = (uint64_t *) OPENSSL_malloc (2 * sizeof (uint64_t));

	// W = B'S
	int i, j, k;
	for (i = 0; i < 12; i++) {
	  for (j = 0; j < 12; j++) {
	    w[i * 12 + j] = 0;
	    for (k = 0; k < 1024; k++) {
	      w[i * 12 + j] += peer_pub_key->b[i * 1024 + k] * priv_pub_key->s[k * 12 + j];
	    }
	  }
	}

        debug_printf("  Computing B'S = "); // DEBUG LINE
	for (i = 0; i < 12 * 12; i++) {
	    debug_printf("0x%08X ", w[i]);
	}
	debug_printf("\n");
	
#if CONSTANT_TIME
	lwe_rec_ct (ka, w, peer_reconciliation->c);
#else
	lwe_rec (ka, w, peer_reconciliation->c);
#endif

        debug_printf("  Computing key K = rec(B'S, C) = "); // DEBUG LINE
	for (i = 0; i < 4; i++) {
          debug_printf("0x%08X ", ((uint32_t *)ka)[i]);
	}
	debug_printf("\n");

	if (KDF != 0) {
		if (KDF((unsigned char *) ka, 2 * sizeof(uint64_t), out, &outlen) == NULL) {
			RLWEKEXerr(RLWEKEX_F_RLWEKEX_COMPUTE_KEY_ALICE, RLWEKEX_R_KDF_FAILED);
			goto err;
		}
		ret = outlen;
	} else {
		/* no KDF, just copy as much as we can */
		if (outlen > 2 * sizeof(uint64_t))
			outlen = 2 * sizeof(uint64_t);
		memcpy(out, (unsigned char *) ka, outlen);
		ret = outlen;
	}

err:
	if (w) OPENSSL_free(w);
	if (ka) OPENSSL_free(ka);
	return (ret);

}

int LWEKEX_compute_key_bob(void *out, size_t outlen, LWE_REC *reconciliation, const LWE_PUB *peer_pub_key,  const LWE_PAIR *priv_pub_key,
			   void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen), LWE_CTX *ctx) {

	int i;
	int ret = -1;

	uint32_t *v  = (uint32_t *) OPENSSL_malloc (12 * 12 * sizeof (uint32_t));
	uint64_t *kb = (uint64_t *) OPENSSL_malloc (2 * sizeof (uint64_t));

	uint32_t *eprimeprime = (uint32_t *) OPENSSL_malloc (12 * 12 * sizeof (uint32_t));
        debug_printf("  Sampling Gaussian noise E'' (%i elements) = ", 12 * 12); // DEBUG LINE
#if CONSTANT_TIME
	lwe_sample_n_ct(eprimeprime, 12 * 12);
#else
	lwe_sample_n(eprimeprime, 12 * 12);
#endif
	for (i = 0; i < 2; i++) {
          debug_printf("0x%08X ", eprimeprime[i]);
        }
	debug_printf("...0x%08X\n", eprimeprime[12 * 12 - 1]);
	
        debug_printf("  Computing V = S'B + E'' = "); // DEBUG LINE

	lwe_key_derive_client(v, peer_pub_key->b, priv_pub_key->s, eprimeprime); // can potentially pass a context in here
	OPENSSL_free(eprimeprime);
	for (i = 0; i < 12 * 12; i++) {
          //debug_printf("0x%08X ", v[i]);
	  binary_printf(v[i], 32);
	  debug_printf(" ");
        }
	debug_printf("\n");
	// printf("...0x%08X\n", v[12 * 12 - 1]);

#if CONSTANT_TIME
        debug_printf("  Computing reconciliation: C = <V>_2\n"); // DEBUG LINE
	lwe_crossround2_ct(reconciliation->c, v);
        debug_printf("  Computing key K = [V]_2 = \n"); // DEBUG LINE
	lwe_round2_ct(kb, v);
#else
        debug_printf("  Computing reconciliation: C = <V>_2\n"); // DEBUG LINE
	lwe_crossround2(reconciliation->c, v);
        debug_printf("  Computing key K = [V]_2 = "); // DEBUG LINE
	lwe_round2(kb, v);
#endif
	for (i = 0; i < 4; i++) {
          // debug_printf("0x%08X ", ((uint32_t *)kb)[i]);
	  binary_printf(kb[i], 64);
	  debug_printf(" ");
	}
	debug_printf("\n");

	if (KDF != 0) {
		if (KDF((unsigned char *) kb, 2 * sizeof(uint64_t), out, &outlen) == NULL) {
			RLWEKEXerr(RLWEKEX_F_RLWEKEX_COMPUTE_KEY_BOB, RLWEKEX_R_KDF_FAILED);
			goto err;
		}
		ret = outlen;
	} else {
		/* no KDF, just copy as much as we can */
		if (outlen > 2 * sizeof(uint64_t))
			outlen = 2 * sizeof(uint64_t);
		memcpy(out, (unsigned char *) kb, outlen);
		ret = outlen;
	}

err:
	if (v) OPENSSL_free(v);
	if (kb) OPENSSL_free(kb);
	return (ret);

}

void print_first_element_REC(const LWE_REC *rec) {
  printf("  First bit of reconciliation structure: %02X\n", ((unsigned char *)rec->c)[0]);
}
