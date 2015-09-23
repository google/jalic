/*
Copyright 2015 Google Inc. All Rights Reserved.

Author: nikolaenko@google.com (Valeria Nikolaenko)
Author: pseudorandom@google.com (Ananth Raghunathan)
Author: mironov@google.com (Ilya Mironov)
*/

/* crypto/lwekex/lwekex_locl.h */

#ifndef HEADER_LWEKEX_LOCL_H
#define HEADER_LWEKEX_LOCL_H

#include <openssl/lwekex.h>

#define CONSTANT_TIME 1

#ifdef  __cplusplus
extern "C" {
#endif

struct lwe_param_st {
  int version;
  uint32_t *a; // 1024 x 1024
  uint32_t *a_transpose; // 1024 x 1024
  int references;
  int	flags;
};

struct lwe_pub_st {
  int version;
  LWE_PARAM *param;
  uint32_t *b; // for Server (1024 x 12), for Client (12 x 1024)
  int references;
  int	flags;
};

struct lwe_pair_st {
  int version;
  LWE_PUB *pub;
  uint32_t *s; // for Server (1024 x 12), for Client (12 x 1024)
  uint32_t *e; // for Server (1024 x 12), for Client (12 x 1024)
  int references;
  int	flags;
};

struct lwe_rec_st {
  int version;
  unsigned char *c; // of size 16 (for 128 bits key)
  int references;
  int	flags;
};

struct lwe_ctx_st {
  int version;
  int references;
  int	flags;
};

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_LWEKEX_LOCL_H */
