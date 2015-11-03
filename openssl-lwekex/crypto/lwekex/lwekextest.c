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

#include "../crypto/lwekex/lwe.h"

#ifdef OPENSSL_NO_LWEKEX
int main(int argc, char *argv[]) {
  printf("No LWEKEX support\n");
  return (0);
}
#else
#include <openssl/lwekex.h>

#ifdef OPENSSL_SYS_WIN16
#define MS_CALLBACK _far _loadds
#else
#define MS_CALLBACK
#endif

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

static const int KDF1_SHA1_len = 20;
static void *KDF1_SHA1(const void *in, size_t inlen, void *out,
                       size_t *outlen) {
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

static int test_pack_unpack(BIO *out, uint32_t *in, size_t inlen,
                            unsigned char msb) {
  int ret = 0;
  int i;

  size_t packed_len = LWE_DIV_ROUNDUP(inlen * msb, 8);
  unsigned char *v_packed = (unsigned char *)OPENSSL_malloc(packed_len);
  uint32_t *v_unpacked = (uint32_t *)OPENSSL_malloc(inlen);

  if (v_packed == NULL || v_unpacked == NULL) {
    fprintf(stderr, "OPENSSL_malloc failed\n");
    goto err;
  }

  BIO_printf(out, "Packing ");
  for (i = 0; i < inlen; i++) BIO_printf(out, "%08X ", in[i]);
  BIO_printf(out, "\n");

  lwe_pack(v_packed, packed_len, in, inlen, msb);

  BIO_printf(out, "Packed result ");
  for (i = 0; i < packed_len; i++) BIO_printf(out, "%02X ", v_packed[i]);
  BIO_printf(out, "\n");

  lwe_unpack(v_unpacked, inlen, v_packed, packed_len, msb);

  BIO_printf(out, "Unpacked result ");
  for (i = 0; i < inlen; i++) BIO_printf(out, "%08X ", v_unpacked[i]);
  BIO_printf(out, "\n");

  uint32_t negmask = (1 << msb) - 1;

  int match = 1;

  for (i = 0; i < inlen; i++)
    if ((in[i] ^ v_unpacked[i]) & negmask) match = 0;

  if (!match) {
    fprintf(stderr, "Pack/unpack failed to match\n");
    goto err;
  }

  ret = 1;
err:
  ERR_print_errors_fp(stderr);

  OPENSSL_free(v_packed);
  OPENSSL_free(v_unpacked);

  return ret;
}

static int test_packing_unpacking(BIO *out) {
  uint32_t a[3] = {0x1, 0x2, 0x3};

  uint32_t b[4] = {0x01000000, 0x02000000, 0x03000000, 0x04000000};

  uint32_t c[5] = {0x01600000, 0x02700000, 0x03800000, 0x04900000, 0x05A00000};

  if (!test_pack_unpack(out, a, 3, 32) || !test_pack_unpack(out, b, 4, 8) ||
      !test_pack_unpack(out, c, 5, 9))
    return 0;

  return 1;
}

static int test_lwekex(BIO *out, int single) {
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
  uint32_t *v =
      (uint32_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N_BAR * sizeof(uint32_t));
  uint32_t *w =
      (uint32_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N_BAR * sizeof(uint32_t));

  alice = LWE_PAIR_new();
  bob = LWE_PAIR_new();
  bob_reconstructed = LWE_PUB_new();
  rec = LWE_REC_new();
  rec_reconstructed = LWE_REC_new();
  ctx = LWE_CTX_new();
  if ((alice == NULL) || (bob == NULL) || (bob_reconstructed == NULL) ||
      (rec == NULL) || (rec_reconstructed == NULL) || (ctx == NULL)) {
    goto err;
  }

  if (single) {
    BIO_puts(out, "Testing packing/unpacking  \n");
    if (!test_packing_unpacking(out))
      ;
    //    goto err;
  }

  if (single) BIO_puts(out, "Testing key generation  \n");

  if (single) BIO_puts(out, "Generating key for Alice (Server)\n");
  if (!LWE_PAIR_generate_key(alice, ctx, 1)) goto err;
  apublen = i2o_LWE_PUB(LWE_PAIR_get_publickey(alice), &apubbuf);
  if (single) BIO_printf(out, "  public B (%d bytes) = ", (int)apublen);
  if (apublen <= 0) {
    fprintf(stderr, "Error in LWEKEX routines\n");
    ret = 0;
    goto err;
  }
  if (single) {
    BIO_printf(out, "0x%02X 0x%02X 0x%02X 0x%02X ... 0x%02X\n", apubbuf[0], apubbuf[1], apubbuf[3], apubbuf[4],
               apubbuf[apublen - 1]);
  }

  if (single) BIO_puts(out, "Generating key for Bob (Client)\n");
  if (!LWE_PAIR_generate_key(bob, ctx, 0)) goto err;
  bpublen = i2o_LWE_PUB(LWE_PAIR_get_publickey(bob), &bpubbuf);
  if (single) {
    BIO_printf(out, "  public B' (%i bytes) = ", (int)bpublen);
    BIO_printf(out, "0x%02X 0x%02X 0x%02X 0x%02X ... 0x%02X\n", bpubbuf[0], bpubbuf[1], bpubbuf[3], bpubbuf[4],
               bpubbuf[apublen - 1]);

/*
    uint32_t *pa = LWE_PAIR_get_privatekey(alice);
    uint32_t *pb = LWE_PAIR_get_privatekey(bob);

    int j1, j2;
    for (j2 = 0; j2 < LWE_N_BAR; j2++)
      for (j1 = 0; j1 < LWE_N_BAR; j1++) {
        int sum = 0;
        for (i = 0; i < LWE_N; i++)
          sum += pa[i * LWE_N_BAR + j1] * pb[j2 * LWE_N + i];

        BIO_printf(out, " cross product (Alice_s[%d] x Bob_s[%d]) = %X\n ", j1,
                   j2, sum);
      }
*/
  }

  if (single) BIO_puts(out, "Testing Bob shared secret generation \n");

  bsslen = KDF1_SHA1_len;
  bssbuf = (unsigned char *)OPENSSL_malloc(bsslen);
  bsslen =
      LWEKEX_compute_key_bob(bssbuf, bsslen, rec, LWE_PAIR_get_publickey(alice),
                             bob, KDF1_SHA1, ctx, v);
  if (single) {
    BIO_printf(out, "  key_B (%i bytes) = ", (int)bsslen);
    for (i = 0; i < bsslen; i++) {
      BIO_printf(out, "%02X", bssbuf[i]);
    }
    BIO_puts(out, "\n");
  }
  reclen = i2o_LWE_REC(rec, &recbuf);
  if (single) {
    BIO_printf(out, "  rec (%i bytes) = ", (int)reclen);
    for (i = 0; i < reclen; i++) {
      BIO_printf(out, "0x%02X ", ((unsigned char *)recbuf)[i]);
    }
    BIO_puts(out, "\n");
  }

  if (single) BIO_puts(out, "Reconstructing Bob's values \n");

  // if (single) BIO_puts(out, "  Bob's key reconstruction from string \n");
  if (o2i_LWE_PUB(&bob_reconstructed, bpubbuf, bpublen) == NULL) {
    fprintf(stderr,
            "Error in LWEKEX routines (Bob public key reconstruction)\n");
    ret = 0;
    goto err;
  }
  // if (single) BIO_puts(out, "  Bob's reconciliation value reconstruction from
  // string \n");
  if (o2i_LWE_REC(&rec_reconstructed, recbuf, reclen) == NULL) {
    fprintf(stderr,
            "Error in LWEKEX routines (Bob reconciliation reconstruction)\n");
    ret = 0;
    goto err;
  }

  if (single) BIO_puts(out, "Testing Alice shared secret generation \n");

  asslen = KDF1_SHA1_len;
  assbuf = (unsigned char *)OPENSSL_malloc(asslen);
  asslen =
      LWEKEX_compute_key_alice(assbuf, asslen, bob_reconstructed,
                               rec_reconstructed, alice, KDF1_SHA1, ctx, w);
  if (single) {
    BIO_printf(out, "  key_A (%i bytes) = ", (int)asslen);
    for (i = 0; i < asslen; i++) {
      BIO_printf(out, "%02X", assbuf[i]);
    }
    BIO_puts(out, "\n");
  }

  if ((bsslen != asslen) || (memcmp(assbuf, bssbuf, asslen) != 0)) {
    if (single) {
      BIO_printf(out, " failed\n\n");
      fprintf(stderr, "Error in LWEKEX routines (mismatched shared secrets)\n");
    }
    ret = 0;
  } else {
    if (single) BIO_printf(out, "ok!\n");
    ret = 1;
  }

  // computing the Hamming distance vector between v and w
  if (single) {
    BIO_printf(out, "Hamming distance between the keys: [");
    for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
      BIO_printf(out, "%08X", v[i] ^ w[i]);
      if (i + 1 < LWE_N_BAR * LWE_N_BAR) BIO_printf(out, ", ");
    }
    BIO_printf(out, "]\n");

    // computing the number of the lsb bits corrupted by noise

    BIO_printf(out,
               "The number of corrupted least significant bits (out of 32): [");
    int count_bits = 0;
    int max = 0;
    for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
      int64_t diff = (int64_t)v[i] - w[i];
      if (diff < 0) diff = -diff;
      count_bits = 0;
      while (diff != 0) {
        count_bits++;
        diff >>= 1;
      }
      if (count_bits > max) max = count_bits;
      BIO_printf(out, "%i", count_bits);
      if (i + 1 < LWE_N_BAR * LWE_N_BAR) BIO_printf(out, ", ");
    }
    BIO_printf(out, "], MAX = %i\n", max);
  }

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
        BIO_printf(out, "Iterations: %d, failures: %d, elapsed time: %ld\n",
                   iterations, failures, time(NULL) - starttime);
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
