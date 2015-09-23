/*
Copyright 2015 Google Inc. All Rights Reserved.

Author: nikolaenko@google.com (Valeria Nikolaenko)
Author: pseudorandom@google.com (Ananth Raghunathan)
Author: mironov@google.com (Ilya Mironov)
*/

/* crypto/lwekex/lwekextest.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../e_os.h"

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#ifdef OPENSSL_NO_LWEKEX
int main(int argc, char *argv[]) {
	printf("No LWEKEX support\n");
	return (0);
}
#else
#include <openssl/lwekex.h>

#ifdef OPENSSL_SYS_WIN16
#define MS_CALLBACK	_far _loadds
#else
#define MS_CALLBACK
#endif

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

static const int KDF1_SHA1_len = 20;
static void *KDF1_SHA1(const void *in, size_t inlen, void *out, size_t *outlen) {
#ifndef OPENSSL_NO_SHA
	if (*outlen < SHA_DIGEST_LENGTH)
		return NULL;
	else
		*outlen = SHA_DIGEST_LENGTH;
	return SHA1(in, inlen, out);
#else
	return NULL;
#endif
}


static int test_lwekex(BIO *out, int single) {
  /*
  uint32_t *out_debug = (uint32_t *)OPENSSL_malloc(2 * sizeof(uint32_t));
  out_debug[0] = out_debug[1] = 0xFFFFFFFF;
  memset(out_debug, 0, 2);
  printf("out = 0x%08X 0x%08X\n", out_debug[0], out_debug[1]);
  OPENSSL_free(out_debug);
  */

	LWE_PAIR *alice = NULL, *bob = NULL;
	LWE_REC *rec = NULL;

	LWE_PUB *bob_reconstructed = NULL;
	LWE_REC *rec_reconstructed = NULL;

	LWE_CTX *ctx = NULL;

	unsigned char *apubbuf = NULL, *bpubbuf = NULL;
	size_t apublen, bpublen;

	unsigned char *recbuf = NULL;
	size_t reclen;

	unsigned char *assbuf = NULL, *bssbuf = NULL;
	size_t asslen, bsslen;

	int i, ret = 0;
	int LWE_N_HAT = 4; // TODO: replace!!!
	uint32_t *v  = (uint32_t *) OPENSSL_malloc (LWE_N_HAT * LWE_N_HAT * sizeof (uint32_t));
	uint32_t *w  = (uint32_t *) OPENSSL_malloc (LWE_N_HAT * LWE_N_HAT * sizeof (uint32_t));

	alice = LWE_PAIR_new();
	bob = LWE_PAIR_new();
	bob_reconstructed = LWE_PUB_new();
	rec = LWE_REC_new();
	rec_reconstructed = LWE_REC_new();
	ctx = LWE_CTX_new ();
	if ((alice == NULL) || (bob == NULL) || (bob_reconstructed == NULL) || (rec == NULL) || (rec_reconstructed == NULL) || (ctx == NULL)) {
		goto err;
	}

	if (single) BIO_puts(out, "Testing key generation  \n");

	if (single) BIO_puts(out, "Generating key for Alice (Server)\n");
	if (!LWE_PAIR_generate_key(alice, ctx, 1)) goto err;
	apublen = i2o_LWE_PUB(LWE_PAIR_get_publickey(alice), &apubbuf);
	if (single) BIO_printf(out, "  public B (%i bytes, %i elements) = ", (int) apublen, (int)apublen / 4);
	if (apublen <= 0) {
		fprintf(stderr, "Error in LWEKEX routines\n");
		ret = 0;
		goto err;
	}
	if (single) {
	  // for (i = 0; i < apublen; i++) {
	  for (i = 0; i < 2; i++) {
	    BIO_printf(out, "0x%08X ", ((uint32_t *)apubbuf)[i]);
	  }
	  BIO_printf(out, "...0x%08X \n", ((uint32_t *)apubbuf)[(apublen / 4) - 1]);
	}

	if (single) BIO_puts(out, "Generating key for Bob (Client)\n");
	if (!LWE_PAIR_generate_key(bob, ctx, 0)) goto err;
	bpublen = i2o_LWE_PUB(LWE_PAIR_get_publickey(bob), &bpubbuf);
	if (single) {
	  BIO_printf(out, "  public B' (%i bytes, %i elements) = ", (int) bpublen, (int) bpublen / 4);
	  // for (i = 0; i < bpublen; i++) {
	  for (i = 0; i < 2; i++) {
	    BIO_printf(out, "0x%08X ", ((uint32_t *)bpubbuf)[i]);
	  }
	  BIO_printf(out, "...0x%08X\n", ((uint32_t *)bpubbuf)[(bpublen / 4) - 1]);
	}

	if (single) BIO_puts(out, "Testing Bob shared secret generation \n");

	bsslen = KDF1_SHA1_len;
	bssbuf = (unsigned char *)OPENSSL_malloc(bsslen);
	bsslen = LWEKEX_compute_key_bob(bssbuf, bsslen, rec,
					LWE_PAIR_get_publickey(alice), bob, KDF1_SHA1, ctx, v);
	if (single) {
		BIO_printf(out, "  key_B (%i bytes) = ", (int) bsslen);
		for (i = 0; i < bsslen; i++) {
			BIO_printf(out, "%02X", bssbuf[i]);
		}
		BIO_puts(out, "\n");
	}
	reclen = i2o_LWE_REC(rec, &recbuf);
	if (single) {
		BIO_printf(out, "  rec (%i bytes) = ", (int) reclen);
		for (i = 0; i < reclen / 4; i++) {
		  BIO_printf(out, "0x%08X ", ((uint32_t *)recbuf)[i]);
		}
		BIO_puts(out, "\n");
	}

	if (single) BIO_puts(out, "Reconstructing Bob's values \n");

	// if (single) BIO_puts(out, "  Bob's key reconstruction from string \n");
	if (o2i_LWE_PUB(&bob_reconstructed, bpubbuf, bpublen) == NULL) {
		fprintf(stderr, "Error in LWEKEX routines (Bob public key reconstruction)\n");
		ret = 0;
		goto err;
	}
	// if (single) BIO_puts(out, "  Bob's reconciliation value reconstruction from string \n");
	if (o2i_LWE_REC(&rec_reconstructed, recbuf, reclen) == NULL) {
		fprintf(stderr, "Error in LWEKEX routines (Bob reconciliation reconstruction)\n");
		ret = 0;
		goto err;
	}

	if (single) BIO_puts(out, "Testing Alice shared secret generation \n");

	asslen = KDF1_SHA1_len;
	assbuf = (unsigned char *)OPENSSL_malloc(asslen);
	asslen = LWEKEX_compute_key_alice(assbuf, asslen, bob_reconstructed, rec_reconstructed, alice, KDF1_SHA1, ctx, w);
	if (single) {
		BIO_printf(out, "  key_A (%i bytes) = ", (int) asslen);
		for (i = 0; i < asslen; i++) {
			BIO_printf(out, "%02X", assbuf[i]);
		}
		BIO_puts(out, "\n");
	}

	if ((bsslen != asslen) || (memcmp(assbuf, bssbuf, asslen) != 0)) {
		BIO_printf(out, " failed\n\n");
		fprintf(stderr, "Error in LWEKEX routines (mismatched shared secrets)\n");
		ret = 0;
	} else {
		if (single) BIO_printf(out, "ok!\n");
		ret = 1;
	}

	// computing the Hamming distance vector between v and w
	uint32_t tmp, min;
	BIO_printf(out, "Hamming distance between the keys: [");
	for (i = 0; i < LWE_N_HAT * LWE_N_HAT; i++) {
	  // computing MIN(v[i] - w[i], w[i] - v[i])
	  min = v[i] - w[i];
	  tmp = w[i] - v[i];
	  if (tmp < min) min = tmp;
	  BIO_printf(out, "%08X", min);
	  if (i + 1 < LWE_N_HAT * LWE_N_HAT) BIO_printf(out, ", ");
	}
	BIO_printf(out, "]\n");
	
	// computing the number of the lsb bits corrupted by noise
	BIO_printf(out, "The number of corrupted least significant bits (out of 32): [");
	int count_bits = 0;
	int max = 0;
	for (i = 0; i < LWE_N_HAT * LWE_N_HAT; i++) {
	  // computing MIN(v[i] - w[i], w[i] - v[i])
	  min = v[i] - w[i];
	  tmp = w[i] - v[i];
	  if (tmp < min) min = tmp;
	  count_bits = 0;
	  while (min != 0) {
	    count_bits++;
	    min >>= 1;	    
	  }
	  if (count_bits > max) max = count_bits;
	  BIO_printf(out, "%i", count_bits);
	  if (i + 1 < LWE_N_HAT * LWE_N_HAT) BIO_printf(out, ", ");
	}
	BIO_printf(out, "], MAX = %i\n", max);

err:
	ERR_print_errors_fp(stderr);

	OPENSSL_free(w);
	OPENSSL_free(v);
	OPENSSL_free(bssbuf);
	OPENSSL_free(assbuf);
	OPENSSL_free(apubbuf);
	OPENSSL_free(bpubbuf);
	OPENSSL_free(recbuf);
	LWE_REC_free(rec_reconstructed);
	LWE_REC_free(rec);
	LWE_PUB_free(bob_reconstructed);
	LWE_PAIR_free(bob);
	LWE_PAIR_free(alice);
	LWE_CTX_free(ctx);
	return (ret);
}

int main(int argc, char *argv[]) {
	int ret = 1;
	BIO *out;

	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

#ifdef OPENSSL_SYS_WIN32
	CRYPTO_malloc_init();
#endif

	RAND_seed(rnd_seed, sizeof rnd_seed);

	out = BIO_new(BIO_s_file());
	if (out == NULL) EXIT(1);
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	if (argc == 1) {
		if (!test_lwekex(out, 1)) goto err;
	} else {
		int iterations = 0;
		int failures = 0;
		time_t starttime = time(NULL);
		while (1) {
			iterations++;
			if (test_lwekex(out, 0) == 1) {
			} else {
				failures++;
			}
			if ((iterations % 100) == 0) {
				BIO_printf(out, "Iterations: %d, failures: %d, elapsed time: %ld\n", iterations, failures, time(NULL) - starttime);
				if (iterations > (1 << 20)) break;
			}
		}
	}

	ret = 0;

err:
	ERR_print_errors_fp(stderr);
	BIO_free(out);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	CRYPTO_mem_leaks_fp(stderr);
	EXIT(ret);
	return (ret);
}

#endif
