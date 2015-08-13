#ifndef _LWE_H_
#define _LWE_H_

#include <stdint.h>

#define LWE_128_N 1024
#define LWE_128_NBAR 12
// seems that nothing restricts the form of the modulus q, so we can stick to 2^32
// which would simply mean that we will be using unsigned 32-bits integer

void lwe_sample_ct(uint32_t *s);
void lwe_sample(uint32_t *s);
void lwe_sample_n_ct(uint32_t *s, int n);
void lwe_sample_n(uint32_t *s, int n);

void lwe_round2_ct(uint64_t *out, const uint32_t *in);
void lwe_round2(uint64_t *out, const uint32_t *in);

void lwe_crossround2_ct(uint64_t *out, const uint32_t *in);
void lwe_crossround2(uint64_t *out, const uint32_t *in);

void lwe_rec_ct(uint64_t *out, const uint32_t *w, const uint64_t *b);
void lwe_rec(uint64_t *out, const uint32_t *w, const uint64_t *b);

// multiply by s on the right
// computes out = as + e
// where a (1024 x 1024), s,e (1024 x 12), 
void lwe_key_gen_server(uint32_t *out, const uint32_t *a, const uint32_t *s, const uint32_t *e);
// multiply by s on the left
// computes out = sa + e
// where a (1024 x 1024), s,e (12 x 1024), 
void lwe_key_gen_client(uint32_t *out, const uint32_t *a, const uint32_t *s, const uint32_t *e);
// multiply by s on the left
// computes out = sb+e
// where b (1024 x 12), s (12 x 1024), e (12 x 12)
void lwe_key_derive_client(uint32_t *out, const uint32_t *b, const uint32_t *s, const uint32_t *e);

#endif /* _LWE_H_ */
