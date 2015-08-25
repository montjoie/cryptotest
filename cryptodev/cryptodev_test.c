/*
 * AES tester/bencher
 *
 * This file is under GPL
 *
 * LABBE Corentin <clabbe.montjoie@gmail.com>
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

struct cryptodev_ctx {
	int cfd;
	struct session_op sess;
	uint16_t alignmask;
};

#define	MAX_KEY_SIZE	32

/*============================================================================*/
/*============================================================================*/
int cryptodev_ctx_init(struct cryptodev_ctx *ctx, int cfd, const uint8_t *key, unsigned int key_size, int algo)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->cfd = cfd;

	ctx->sess.cipher = algo;
	ctx->sess.keylen = key_size;
	ctx->sess.key = (void *)key;

	if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess)) {
		fprintf(stderr, "ERROR: ioctl(CIOCGSESSION) %s",
				strerror(errno));
		return -1;
	}

	return 0;
}

/*============================================================================*/
/*============================================================================*/
void aes_ctx_deinit(struct cryptodev_ctx *ctx)
{
	if (ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses)) {
		fprintf(stderr, "ERROR: ioctl(CIOCFSESSION) %s",
				strerror(errno));
	}
}

/*============================================================================*/
/*============================================================================*/
int aes_encrypt(struct cryptodev_ctx *ctx, const void *iv,
		const void *plaintext, void *ciphertext, size_t size)
{
	struct crypt_op cryp;

	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.src = (void *)plaintext;
	cryp.dst = ciphertext;
	cryp.iv = (void *)iv;
	cryp.op = COP_ENCRYPT;

	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		fprintf(stderr, "ERROR: aes_encrypt ioctl(CIOCCRYPT) %s",
				strerror(errno));
		return -1;
	}
	return 0;
}

/*============================================================================*/
/*============================================================================*/
int aes_decrypt(struct cryptodev_ctx *ctx, const void *iv,
		const void *ciphertext, void *plaintext, size_t size)
{
	struct crypt_op cryp;

	memset(&cryp, 0, sizeof(struct crypt_op));

	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.src = (void *)ciphertext;
	cryp.dst = plaintext;
	cryp.iv = (void *)iv;
	cryp.op = COP_DECRYPT;

	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		fprintf(stderr, "ERROR: aes_decrypt ioctl(CIOCCRYPT) %s",
				strerror(errno));
		return -1;
	}
	return 0;
}

/*============================================================================*/
/*============================================================================*/
static int test_aes(int cfd, int do_bench, unsigned int nr, unsigned int keysize)
{
	unsigned char iv[AES_BLOCK_SIZE];
	uint8_t key[MAX_KEY_SIZE];
	struct cryptodev_ctx ctx;
	const size_t data_len = 1024 * 1024 * 4;
	int out_len = data_len;
	unsigned char *src, *dst, *odst, *ddst;
	int i, j, k, err = 0;
	struct timeval begin;
	struct timeval now;
	unsigned int nb_request = nr;
	float nb_usec;
	size_t rsize;
	EVP_CIPHER_CTX en;

	dst = malloc(data_len);
	if (dst == NULL) {
		fprintf(stderr, "Cannot malloc dst %s\n", strerror(errno));
		err = errno;
		goto test_end;
	}
	src = malloc(data_len);
	if (src == NULL) {
		fprintf(stderr, "Cannot malloc src %s\n", strerror(errno));
		err = errno;
		goto test_end;
	}
	odst = malloc(data_len);
	if (odst == NULL) {
		fprintf(stderr, "Cannot malloc odst %s\n", strerror(errno));
		err = errno;
		goto test_end;
	}
	ddst = malloc(data_len);
	if (ddst == NULL) {
		fprintf(stderr, "Cannot malloc ddst %s\n", strerror(errno));
		err = errno;
		goto test_end;
	}

	for (j = 0; j < 17; j++) {
		rsize = 16 << j;
		/* Generate random key and IV */
		for (k = 0; k < keysize; k++)
			key[k] = rand() % 255;
		for (k = 0; k < sizeof(iv); k++)
			iv[k] = rand() % 255;
		if (do_bench == 1) {
			cryptodev_ctx_init(&ctx, cfd, key, keysize, CRYPTO_AES_CBC);
		}
		if (do_bench == 0) {
			EVP_CIPHER_CTX_init(&en);
			switch (keysize) {
			case 16:
				EVP_EncryptInit_ex(&en, EVP_aes_128_cbc(), NULL, key, iv);
				break;
			case 24:
				EVP_EncryptInit_ex(&en, EVP_aes_192_cbc(), NULL, key, iv);
				break;
			case 32:
				EVP_EncryptInit_ex(&en, EVP_aes_256_cbc(), NULL, key, iv);
				break;
			default:
				fprintf(stderr, "ERROR: invalid keysize %d\n", keysize);
				err = -1;
				goto test_end;
			}
			EVP_CIPHER_CTX_set_padding(&en, 0);
			EVP_EncryptUpdate(&en, odst, &out_len, src, rsize);
			EVP_CIPHER_CTX_cleanup(&en);
			if (out_len > data_len || out_len > rsize) {
				fprintf(stderr, "ERROR: %u %u %u\n", out_len, data_len, rsize);
			}
		}
		nb_request = nr;
		if (rsize == 16)
			nb_request = nr * 100;
		if (rsize == 32)
			nb_request = nr * 10;
		if (rsize == 64)
			nb_request = nr * 10;
		if (rsize == 128)
			nb_request = nr * 10;
		if (j > 9 && nb_request > 10000)
			nb_request = 10000;
		if (j > 13 && nb_request > 5000)
			nb_request = 5000;
		if (j > 15 && nb_request > 1000)
			nb_request = 1000;
		if (j > 16 && nb_request > 500)
			nb_request = 500;
		gettimeofday(&begin, NULL);
		for (i = 0 ; i < nb_request; i++) {
			if (do_bench == 0) {
				cryptodev_ctx_init(&ctx, cfd, key, keysize, CRYPTO_AES_CBC);
			}
			aes_encrypt(&ctx, iv, src, dst, rsize);

			if (do_bench == 0) {
				aes_ctx_deinit(&ctx);
				if (memcmp(dst, odst, rsize) != 0) {
					for (k = 0; k < rsize; k++) {
						if (dst[k] != odst[k])
							break;
					}
					fprintf(stderr, "Error at encrypt request %d pos=%d of len=%u\n", i, k, rsize);
					for (i = 0; i < rsize && i < 24; i++) {
						printf("%02x %02x\n", odst[i], dst[i]);
					}
					err = -1;
					goto test_end;
				}
				cryptodev_ctx_init(&ctx, cfd, key, keysize, CRYPTO_AES_CBC);
				aes_decrypt(&ctx, iv, dst, ddst, rsize);
				aes_ctx_deinit(&ctx);
				if (memcmp(src, ddst, rsize) != 0) {
					/* find the offset of the first error */
					for (k = 0; k < rsize; k++) {
						if (src[k] != ddst[k])
							break;
					}
					fprintf(stderr, "Decrypt error at request %d pos=%d of len=%u key=%d\n",
							i, k, rsize, keysize);
					for (i = 0; i < keysize; i++)
						printf("key%02d %02x\n", i, key[i]);
					for (i = 0; i < rsize && i < 16; i++) {
						printf("%02x %02x\n", src[i], ddst[i]);
					}
					if (k > 4)
						k -= 4;
					for (i = k; i < rsize && i < k + 32; i++) {
						printf("%d %02x %02x\n", i, src[i], ddst[i]);
					}
					err = -1;
					goto test_end;
				}
			}
		}
		if (do_bench == 1) {
			aes_ctx_deinit(&ctx);
		}
		gettimeofday(&now, NULL);
		nb_usec = now.tv_usec + (now.tv_sec - begin.tv_sec) * 1000000 - begin.tv_usec;
		printf("STAT %u requests of %d AES %u in %fus (%fs) %fr/us %fr/ms %fr/s\n", nb_request, rsize, keysize,
				nb_usec, nb_usec / 1000000,
				(float) nb_request / nb_usec,
				(float) nb_request * 1000 / nb_usec,
				(float) nb_request * 1000000 / nb_usec
		      );
	}

	aes_ctx_deinit(&ctx);
	printf("AES %d Test passed\n", keysize * 8);
test_end:
	free(src);
	free(dst);
	free(ddst);
	free(odst);

	return err;
}

/*============================================================================*/
/*============================================================================*/
int main(const int argc, const char **argv)
{
	int cfd = -1;
	int do_bench = -1; /* 0 for test mode, 1 for bench mode */
	int num_request = 1000;

	if (argc < 2) {
		fprintf(stderr, "%s [bench|test] [md5|sha1|aes] [numberofrequest]\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (argc > 1 && strcmp("bench", argv[1]) == 0) {
		printf("Mode bench\n");
		do_bench = 1;
	}
	if (argc > 1 && strcmp("test", argv[1]) == 0) {
		printf("INFO: Mode test\n");
		do_bench = 0;
	}
	if (do_bench == -1)
		return EXIT_FAILURE;
	if (argc > 3) {
		printf("Set requests to %s\n", argv[3]);
		errno = 0;
		num_request = strtoul(argv[3], NULL, 10);
		if (errno != 0) {
			fprintf(stderr, "ERROR: Invalid number of requests\n");
			return EXIT_FAILURE;
		}
	}

	/* Open the crypto device */
	cfd = open("/dev/crypto", O_RDWR, 0);
	if (cfd < 0) {
		fprintf(stderr, "ERROR: Fail to open /dev/crypto %s\n",
				strerror(errno));
		return EXIT_FAILURE;
	}

	OpenSSL_add_all_algorithms();

	if (fcntl(cfd, F_SETFD, 1) == -1) {
		fprintf(stderr, "ERROR: Fail to fcntl(F_SETFD) %s\n",
				strerror(errno));
		return EXIT_FAILURE;
	}

	if (test_aes(cfd, do_bench, num_request, 16))
		return 1;
	if (test_aes(cfd, do_bench, num_request, 24))
		return 1;
	if (test_aes(cfd, do_bench, num_request, 32))
		return 1;

	if (close(cfd)) {
		fprintf(stderr, "ERROR: close(cfd)");
		return EXIT_FAILURE;
	}

	EVP_cleanup();

	return EXIT_SUCCESS;
}
