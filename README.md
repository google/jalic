Post-quantum key exchange from the learning with errors problem
===============================================================

(Some of this code is based off https://github.com/dstebila/openssl-rlwekex.)

This software implements a key exchange protocol from the learning with errors
(LWE) problem. It additionally contains optimizations for reducing the
bandwidth of the protocol.

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




