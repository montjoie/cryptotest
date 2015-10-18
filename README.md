# cryptotest
Tools for testing kernel ciphers and hash algorithm

Testing and benching kernel ciphers and hash could be a difficult task.
So there is a set of tools for helping doing that.

Three way to use kernel crypto API are used:
* AF_ALG socket algorithm
* cryptodev API http://cryptodev-linux.org/
* a kernel module

# installation
```Shell
autoreconf --install

./configure

make
```

# AF_ALG

The af_alg_test tool permit to test AES and MD5/SHA1.
Two mode are proposed, test and bench.
* The test mode will try to hash/cipher data from 16 to 2097152 bytes
and check the result with the same operation done by the openssl lib.
* The bench mode will simply bench x times some operations.

## Usage:
```Shell
af_alg_test [md5|sha1|aes] [check|number_of_request]
```

# cryptodev

The cryptodev_test tool permit to test AES.
Two mode are proposed, test and bench.
* The test mode will try to cipher data from 16 to 2097152 bytes
and check the result with the same operation done by the openssl lib.
* The bench mode will simply bench x times some operations.

## Usage:
```Shell
cryptodev_test test aes number_of_request

cryptodev_test bench aes number_of_request
```

# kernel

The kernel module named cryptotest, check cbc(aes), md5, sha1 using the crypto API.

## Usage
```Shell
make
insmod cryptotest.ko
```

