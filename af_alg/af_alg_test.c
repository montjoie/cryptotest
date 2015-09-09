#include <fcntl.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/types.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <linux/if_alg.h>
#include <stdlib.h>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * http://lwn.net/Articles/410848/
 * http://lwn.net/Articles/410833/
 * https://lkml.org/lkml/2011/8/30/264
 *
 * */

/* found in /usr/src/linux/include/linux/socket.h */
#define SOL_ALG 279

static int debug;
#define BENCH_MD5 0
#define BENCH_SHA1 1
#define BENCH_AES 2

#define DATA_LEN (1024 * 1024 * 4)

unsigned char *data;
static unsigned char dst[DATA_LEN];
static unsigned char openssl_result[DATA_LEN];
static unsigned char ddst[DATA_LEN];

/*============================================================================*/
/*============================================================================*/
/* cipher buff in openssl_result */
static int openssl_aes(const unsigned char *buff, size_t off, size_t len, const unsigned char *iv, const unsigned char *key)
{
	int out_len = sizeof(openssl_result);

	EVP_CIPHER_CTX en;

	EVP_CIPHER_CTX_init(&en);

        EVP_EncryptInit_ex(&en, EVP_aes_128_cbc(), NULL, key, iv);

	EVP_CIPHER_CTX_set_padding(&en, 0);

	EVP_EncryptUpdate(&en, openssl_result, &out_len, buff, len);
	EVP_CIPHER_CTX_cleanup(&en);
	return 0;
}

/*============================================================================*/
/*============================================================================*/
static int openssl_md5(const unsigned char *buf, size_t off, size_t len)
{
	unsigned int md_len;

	EVP_MD_CTX *mdctx;
	const EVP_MD *md;

	md = EVP_get_digestbyname("MD5");
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, buf + off, len);
	EVP_DigestFinal_ex(mdctx, openssl_result, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	return 0;
}

/*============================================================================*/
/*============================================================================*/
static int openssl_sha1(const unsigned char *buf, size_t off, size_t len)
{
	unsigned int md_len;

	EVP_MD_CTX *mdctx;
	const EVP_MD *md;

	md = EVP_get_digestbyname("SHA1");
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, buf + off, len);
	EVP_DigestFinal_ex(mdctx, openssl_result, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	return 0;
}

/*============================================================================*/
/*============================================================================*/
/* Use AF_ALG to perform an operation with algo 
 * from buff to buff_dst
 * both buffer needed to be at least len sized
 * for cipher operation way need to be ALG_OP_ENCRYPT or ALG_OP_DECRYPT */
static int af_alg_do(const unsigned char *buff, size_t off, size_t len, int algo, const unsigned char *key, const unsigned keylen, const unsigned char *iv, unsigned char *buff_dst, int way)
{
	int opfd;
	int tfmfd;
	ssize_t ret;
	char buf[8192];
	int err = 0;
	size_t sended = 0;
	size_t tosend = len;
	ssize_t sent;

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "md5"
	};
	struct sockaddr_alg sa_sha1 = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha1"
	};
	struct sockaddr_alg sa_aes = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(aes)"
	};


	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd < 0) {
		fprintf(stderr, "Error socket %s\n", strerror(errno));
		return -1;
	}

	switch(algo) {
	case BENCH_MD5:
		ret = bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
		if (debug > 0)
			printf("Bench MD5\n");
		break;
	case BENCH_SHA1:
		ret = bind(tfmfd, (struct sockaddr *)&sa_sha1, sizeof(sa_sha1));
		if (debug > 0)
		printf("Bench SHA1\n");
		break;
	case BENCH_AES:
		ret = bind(tfmfd, (struct sockaddr *)&sa_aes, sizeof(sa_aes));
		break;
	default:
		close(tfmfd);
		fprintf(stderr, "Unknown algo %d\n", algo);
		return -1;
	}

	if (ret < 0) {
		fprintf(stderr, "ERROR: bind %s\n", strerror(errno));
		return -1;
	}
/*	printf("DEBUG bind %d\n", ret);*/
	if (algo == BENCH_AES) {
		ret = setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen);
		if (ret < 0) {
			fprintf(stderr, "Error setsockopt %s\n", strerror(errno));
			return -1;
		}
	}

	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		fprintf(stderr, "ERROR: accept %s\n", strerror(errno));
		return -1;
	}
/*	printf("DEBUG accept %d\n", ret);*/

	if (algo == BENCH_AES) {
		struct msghdr msg = {};
		struct cmsghdr *cmsg;
		char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {};
		struct iovec iov;
		struct af_alg_iv *aiv;
		__u32 optype = way;

		if (debug > 0)
			printf("DEBUG: Do AES len=%zd\n", len);

		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_OP;
		cmsg->cmsg_len = CMSG_LEN(4);
		memcpy(CMSG_DATA(cmsg), &optype, 4);

		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_IV;
		cmsg->cmsg_len = CMSG_LEN(20);
		aiv = (void *)CMSG_DATA(cmsg);
		aiv->ivlen = AES_BLOCK_SIZE;
		memcpy(aiv->iv, iv, AES_BLOCK_SIZE);

#define STEP 48000
		sended = 0;
		while (sended < len) {
			iov.iov_base = (void *)buff + sended;
			if (len - sended < STEP)
				iov.iov_len = len - sended;
			else
				iov.iov_len = STEP;
			msg.msg_flags = 0;
			/*iov.iov_len = len - sended;*/
			if (debug > 0)
				printf("DEBUG: Will send offset=%zd len=%zd total=%zd\n", sended, iov.iov_len, len);
			msg.msg_iovlen = 0;
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;

			sent = sendmsg(opfd, &msg, 0);

			if (debug > 0)
				printf("DEBUG: sendmsg ret=%zd %x %s\n", sent, msg.msg_flags, strerror(errno));

			if (sent < 0) {
				fprintf(stderr, "send error %s\n", strerror(errno));
				err = sent;
				goto test_end;
			}
			ret = read(opfd, buff_dst + sended, sent);
			if (debug > 0)
				printf("DEBUG: recv %zd\n", ret);
			if (ret != sent) {
				fprintf(stderr, "Did not receive the right amount of data\n");
				err = -1;
				goto test_end;
			}
			sended += sent;
			if (debug > 0)
				printf("DEBUG: sended %zd/%zd\n", sended, len);

			/* do not update IV for following chunks */
			msg.msg_controllen = 0;
		}
		err = 0;
		goto test_end;
	}

toto:
	if (debug > 0)
		printf("DEBUG: send len=%zd off=%zd\n", tosend, off);
	ret = send(opfd, buf + off, tosend, MSG_MORE);
	if (ret < 0) {
		fprintf(stderr, "ERROR: send %s\n", strerror(errno));
		err = ret;
		goto test_end;
	}
	if (debug > 0)
		printf("DEBUG: send %zd %zd\n", ret, sended);
	sended += ret;
	if (sended < len) {
		tosend -= ret;
		goto toto;
	}

	if (debug > 0)
		printf("DEBUG recv tgt=%zd\n", sizeof(buff_dst));
	ret = read(opfd, buff_dst, sizeof(buff_dst));
	if (ret < 0) {
		fprintf(stderr, "Error de read %s\n", strerror(errno));
		err = ret;
		goto test_end;
	}
	if (debug > 0)
		printf("DEBUG: read %zd\n", ret);

test_end:
	close(opfd);
	close(tfmfd);
	return err;
}

/*============================================================================*/
/*============================================================================*/
int do_check(const unsigned char *data, const size_t data_len) {
	int i, j, ret;
	unsigned char key[16] =
		"\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
		"\x51\x2e\x03\xd5\x34\x12\x00\x06";
	unsigned char iv[16] = 
		"\x3d\xaf\xba\x42\x9d\x9e\xb4\x30"
		"\xb4\x22\xda\x80\x2c\x9f\xac\x41";

	goto do_check_aes;
	/* checks current MD5 implementation */
	printf("do_checktoto\n");
	for (i = 0; i < 4096; i++) {
		af_alg_do(data, 0, i, BENCH_MD5, NULL, 0, NULL, dst, 0);
		openssl_md5(data, 0, i);
			ret = 0;
		for (j = 0; j < MD5_DIGEST_LENGTH; j++) {
			printf("do_checktoto\n");
			if (dst[j] != openssl_result[j])
				ret = 1;
		}
		if (ret == 0) {
			printf("Check ok for MD5 test %d\n", i);
		} else {
			printf("Check failed for MD5 test %d\n", i);
			return -1;
		}
	}
	return 0;
	/* checks current SHA1 implementation */
	for (i = 0; i < 4096; i++) {
		af_alg_do(data, 0, i, BENCH_SHA1, NULL, 0, NULL, dst, 0);
		openssl_sha1(data, 0, i);
		ret = 0;
		for (j = 0; j < SHA_DIGEST_LENGTH; j++) {
			/*printf("%02x", result[j]);*/
			if (dst[j] != openssl_result[j])
				ret = 1;
		}
		if (ret == 0) {
			if (debug > 0)
				printf("Check ok for SHA1 test %d\n", i);
		} else {
			printf("Check failed for SHA1 test %d\n", i);
			return -1;
		}
	}

do_check_aes:
	/* checks current AES implementation *//* 65540 */
	for (i = 16; i < 48000 * 2; i+= 16) {
		if ((i % 4096) == 0)
			printf("INFO: len=%d\n", i);
		/*memset(result, 0, DATA_LEN);*/
		af_alg_do(data, 0, i, BENCH_AES, key, 16, iv, dst, ALG_OP_ENCRYPT);
		openssl_aes(data, 0, i, iv, key);
		ret = -1;
		for (j = 0; j < i && ret == -1; j++) {
			if (dst[j] != openssl_result[j]) {
				ret = j;
				break;
			}
		}
		if (ret < 0) {
			if (debug > 0)
				printf("DEBUG: Check ok for AES test %d\n", i);
		} else {
			printf("ERROR: Check failed for AES cipher test %d at %d\n", i, ret);
			/* dump the data for easy match */
			j = ret - 8;
			if (ret < 8)
				j = 0;
			for (; j < i && j < ret + 8; j++) {
				printf("%04d d=%02x r=%02x o=%02x\n", j, data[j], dst[j], openssl_result[j]);
			}
			return -1;
		}
		/* no check for decypher */
		memset(ddst, 0x66, DATA_LEN);
		af_alg_do(dst, 0, i, BENCH_AES, key, 16, iv, ddst, ALG_OP_DECRYPT);
		ret = -1;
		for (j = 0; j < i && ret == -1; j++) {
			if (ddst[j] != data[j]) {
				ret = j;
				break;
			}
		}
		if (ret < 0) {
			if (debug > 0)
				printf("DEBUG: Check ok for AES test %d\n", i);
		} else {
			printf("ERROR: Check failed for AES decypher test %d at %d\n", i, ret);
			/* dump the data for easy match */
			j = ret - 8;
			if (ret < 8)
				j = 0;
			for (; j < i && j < ret + 8; j++) {
				printf("%04d d=%02x r=%02x o=%02x\n", j, data[j], ddst[j], openssl_result[j]);
			}
			return -1;
		}
	}
	return 0;
}

/*============================================================================*/
/*============================================================================*/
/* Generate data to use in fname
 * return the fd in case of success */
int generate_benchdata(const char *fname, const int randomfd) {
	int fdata;
	ssize_t ret;

	if (fname == NULL || randomfd < 0) {
		return -1;
	}

	printf("INFO: Generating data in %s\n", fname);
	fdata = open(fname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fdata < 0) {
		fprintf(stderr, "ERROR: Failed tod create %s: %s\n", fname, strerror(errno));
		return -1;
	}
	ret = read(randomfd, data, DATA_LEN);
	if (ret < 0) {
		fprintf(stderr, "ERROR: read random %s: %s\n", fname, strerror(errno));
		return -1;
	}
	ret = write(fdata, data, DATA_LEN);
	if (ret < 0) {
		fprintf(stderr, "ERROR: writing to %s: %s\n", fname, strerror(errno));
		return -1;
	}
	ret = lseek(fdata, 0, SEEK_SET);
	if (ret < 0 ) {
		fprintf(stderr, "ERROR: Failed to lseek %s\n", strerror(errno));
	}
	return fdata;
}

/*============================================================================*/
/*============================================================================*/
int main(const int argc, const char *argv[])
{
	int i, randomfd = -1, j;
	struct timeval begin;
	struct timeval now;
	float nb_request = 1000;
	float nb_usec;
	ssize_t ret;
	size_t rsize;
	const size_t data_len = DATA_LEN;
	int less_size = 0;
	int fdata;
	int fdr = -1, err = 0;
	int benched_algo;/* 0=MD5 1=SHA1 2=AES*/
	char buf_result[8192];
	unsigned char key[16] =
		"\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
		"\x51\x2e\x03\xd5\x34\x12\x00\x06";
	unsigned char iv[16] = 
		"\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41";

	if (argc < 2) {
		fprintf(stderr, "%s [md5|sha1|aes] [check|numberofrequest]\n", argv[0]);
		return -1;
	}

	OpenSSL_add_all_algorithms();

	data = malloc(data_len);
	if (data == NULL) {
		fprintf(stderr, "ERROR: Cannot malloc: %s\n", strerror(errno));
		return -1;
	}
/*
	if (argc > 1 && strcmp("check", argv[1]) == 0) {
		err = do_check(data, data_len);
		goto bench_end;
	}
*/
	benched_algo = -1;
	if (strcmp("md5", argv[1]) == 0)
		benched_algo = BENCH_MD5;
	else if (strcmp("sha1", argv[1]) == 0)
		benched_algo = BENCH_SHA1;
	else if (strcmp("aes", argv[1]) == 0)
		benched_algo = BENCH_AES;
	if (benched_algo == -1) {
		err = -1;
		fprintf(stderr, "ERROR: Unknow algorithm %s\n", argv[1]);
		goto bench_end;
	}

	errno = 0;
	if (argc > 2) {
		nb_request = strtoul(argv[2], NULL, 10);
		if (errno != 0 || nb_request < 0) {
			fprintf(stderr, "ERROR: Invalid number of requests\n");
			err = -1;
			goto bench_end;
		}
	}

	if (nb_request == 0) {
		debug = 0;
		do_check(data, 16);
		goto bench_end;
	}

	if (argc > 4) {
		errno = 0;
		less_size = strtol(argv[3], NULL, 10);
		if (errno != 0) {
			fprintf(stderr, "ERROR Invalid less_size\n");
			err = -1;
			goto bench_end;
		}
		printf("INFO: less_size of %d\n", less_size);
	}

	printf("INFO: %s will do %f request\n", argv[0], nb_request);

	randomfd = open("/dev/urandom", O_RDONLY);
	if (randomfd < 0) {
		fprintf(stderr, "ERROR: Cannot open /dev/urandom\n");
		err = randomfd;
		goto bench_end;
	}

	fdr = open("results", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fdr < 0) {
		fprintf(stderr, "ERROR: Cannot create results %s\n", strerror(errno));
		err = fdr;
		goto bench_end;
	}

	debug = 0;

	fdata = open("benchdata", O_RDONLY);
	if (fdata < 0) {
		fdata = generate_benchdata("benchdata", randomfd);
		if (fdata < 0) {
			err = fdata;
			goto bench_end;
		}
	}

	ret = read(fdata, data, data_len);
	if (ret < 0) {
		fprintf(stderr, "ERROR: Read error of fdata %s\n", strerror(errno));
		err = -1;
		goto bench_end;
	}


	for (j = 0; j < 18; j++) {
		gettimeofday(&begin, NULL);
		rsize = 16 << j;
		if (rsize == 131072)
			nb_request /= 10;
		for (i = 0; i < nb_request; i++) {
			af_alg_do(data, 0, rsize - less_size, benched_algo, key, 16, iv, dst, ALG_OP_ENCRYPT);
		}
		gettimeofday(&now, NULL);
		nb_usec = now.tv_usec + (now.tv_sec - begin.tv_sec) * 1000000 - begin.tv_usec;
		printf("%s %f requests of %zd in %fus (%fs) %fr/us %fr/ms %fr/s\n",
				argv[1],
				nb_request, rsize - less_size,
				nb_usec, nb_usec / 1000000,
				nb_request / nb_usec,
				nb_request * 1000 / nb_usec,
				nb_request * 1000000 / nb_usec
		      );
		/*number of request;r/s*/
		ret = snprintf(buf_result, sizeof(buf_result), "%zd;%d;%d\n",
				rsize,
				(int)nb_request, (int)(nb_request * 1000000 / nb_usec));
		ret = write(fdr, buf_result, ret);
	}
bench_end:
	close(randomfd);
	close(fdr);
	free(data);
	EVP_cleanup();

	return err;
}

