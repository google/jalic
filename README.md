Post-quantum key exchange from the learning with errors problem
===============================================================

(Some of this code is based off https://github.com/dstebila/openssl-rlwekex.)

This software implements a key exchange protocol from the learning with errors
(LWE) problem. It additionally contains optimizations for reducing the
bandwidth of the protocol. For further details, see the extended abstract
available at: https://github.com/google/jalic/blob/master/lwe-key-exchange.pdf

Installation
------------
The software is written in plain C (C99) compiled with GCC on the Linux
(x86\_64) platform.

To compile:
```
cd openssl-lwekex
./configure
make depend
make
```

Benchmarks
----------

To get timing information for key generation and key derivation:
```
apps/openssl speed lwekex
```

To see message sizes during protocol execution, first run a server:
```
apps/openssl s_server -cert ../testcert.pem -accept 4433
```

Then, a client:
```
apps/openssl s_client -connect localhost:4433 -cipher LWE-RSA-AES128-GCM-SHA256 -msg
```

In the output, message bytes are annotated with their length as follows:
```
...
    e5 44 34 4d f9 f4 ec 32 6d 85 19 19 95 90 39 2e
    ad 1f 13 d2 78 a9 d4 0b c0 43 97 e2 15 9a fd c0
    40 d0 ad 05 de df a4 55 b8 0c
>>> TLS 1.2 Handshake [length 0004], ServerHelloDone
    0e 00 00 00
>>> TLS 1.2 Handshake [length 270a], ClientKeyExchange
    10 00 27 06 27 00 c0 8d 3f e0 14 ff f7 bf 57 4f
    5e 08 2d 6b a1 d0 5b 68 2e 71 5b ea ab 3e d0 5b
    fe 7d b7 3f 2a cd 97 8c 11 7e 5e 91 00 f6 c3 82
    6c 57 0c 2d c3 5f ae d6 5c 5c ac 4f 7e ef d7 bd
    39 4c a7 99 27 fb 0f 8f 52 9d d5 5b ff a8 fa 43
    c1 3e 4a c2 73 92 15 46 9c 94 73 20 59 70 6b 1b
...
```
The message length in the client's key exchange step is `0x270a` or 9994 bytes.


Tests
-----
To run one key exchange that tests the quality of sampling and the correctness
of key exchange, run:
```
test/lwekextest
```

To run a continuous test that tests reconciliation error rates, run:
```
test/lwekextest cont
```

To switch between constant and non-constant time, appropriately set the flag
`CONSTANT_TIME` to `1` or `0` respectively in
`openssl-lwekex/crypto/lwekex/lwekex_locl.h`.
