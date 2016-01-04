/*
 * Module for checking crypto API more precisely than tcrypt
 * TODO:
 * - benching
 * - cipher part does not use multi SG but one SG of 4096
 *
 * Copyright (C) 2013-2015 LABBE Corentin <clabbe.montjoie@gmail.com>i
 */

#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/rng.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <linux/jiffies.h>

#define MODNAME "ciphertest"

#define DEBUG
#define TEST_HASH

struct tcrypt_result {
	struct completion completion;
	int err;
};

static void test_ablkcipher_cb(struct crypto_async_request *req, int error)
{
	struct tcrypt_result *result = req->data;

	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
	pr_debug("%s Encryption finished successfully\n", MODNAME);
}

/* test algo and set hash result in result*/
static int do_hash_test(const char *algo, u8 *result, int nbsg,
			struct scatterlist *sgs, int nb_up_max)
{
	int ret = 0;
	int i;
	struct crypto_ahash *tfm;
	struct ahash_request *req;
	struct tcrypt_result tresult;

	tfm = crypto_alloc_ahash(algo, 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err("%s ERROR: cannot alloc %s: %d\n", MODNAME, algo, ret);
		return ret;
	}

	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto error_t_hash;
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					test_ablkcipher_cb, &tresult);


	/* set the request to be done from sgi (len=nbsg) to hresult*/
	ahash_request_set_crypt(req, sgs, result, nbsg);
	init_completion(&tresult.completion);

	ret = crypto_ahash_init(req);
	if (ret != 0) {
		pr_err("ERROR: crypto_ahash_init\n");
		goto error_t_req;
	}
/*	pr_info("bench: init %s len=%d nbup=%d\n",
	  crypto_tfm_alg_driver_name(crypto_ahash_tfm(tfm)), nbsg, nb_up_max);*/

	for (i = 0; i < nb_up_max; i++) {
		ret = crypto_ahash_update(req);
		switch (ret) {
		case 0:
			pr_debug("%s: OK\n", MODNAME);
			break;
		case -EINPROGRESS:
		case -EBUSY:
			pr_debug("%s: On wait\n", MODNAME);
			ret = wait_for_completion_interruptible(&tresult.completion);
			break;
		default:
			pr_info("%s: DEFAULT\n", MODNAME);
		}
	}

	ret = crypto_ahash_final(req);
	switch (ret) {
	case 0:
		pr_debug("%s: OK\n", MODNAME);
		break;
	case -EINPROGRESS:
	case -EBUSY:
		pr_debug("%s: On wait\n", MODNAME);
		ret = wait_for_completion_interruptible(&tresult.completion);
		break;
	default:
		pr_info("%s: DEFAULT\n", MODNAME);
	}

error_t_req:
	ahash_request_free(req);
error_t_hash:
	crypto_free_ahash(tfm);
	return ret;
}

/*
 * Test a specific cipher
 * First step cipher a buffer with the kernel cipher
 * Then cipher the same buffer with the tested cipher
 * and then decrypt the dst buffer to test decypher
 *
 * @way	0 for cipher, 1 for decypher
 */
static int do_test_cipher(const char *algo, char *iv,
	const unsigned char *key, const unsigned int key_size,
	struct scatterlist *sgin, struct scatterlist *sgout,
	unsigned int taille, int way)
{
	struct crypto_ablkcipher *tfm;
	struct ablkcipher_request *req;
	int ret;
	struct tcrypt_result result;

	tfm = crypto_alloc_ablkcipher(algo, 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err("ERROR: cannot alloc %s: %d\n", algo, ret);
		return ret;
	}

	req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
	if (IS_ERR(req)) {
		pr_err("ERROR: ablkcipher_request_alloc\n");
		ret = PTR_ERR(req);
		goto error_tfm;
	}

	ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					test_ablkcipher_cb, &result);

	pr_debug("%s: Testing: %s len=%u\n", MODNAME,
		 crypto_tfm_alg_driver_name(crypto_ablkcipher_tfm(tfm)),
		 taille);

	ret = crypto_ablkcipher_setkey(tfm, key, key_size);
	if (ret != 0) {
		pr_err("ERROR: crypto_ablkcipher_setkey\n");
		goto error_req;
	}

	pr_debug("%s: IV %d %zd\n", MODNAME, crypto_ablkcipher_ivsize(tfm),
		 strlen(iv));

	ablkcipher_request_set_crypt(req, sgin, sgout, taille, iv);
	init_completion(&result.completion);

	if (way == 0)
		ret = crypto_ablkcipher_encrypt(req);
	else
		ret = crypto_ablkcipher_decrypt(req);

	/*ret = crypto_ablkcipher_decrypt(req);*/
	switch (ret) {
	case 0:
		pr_debug("%s: OK\n", MODNAME);
		break;
	case -EINPROGRESS:
	case -EBUSY:
		pr_debug("%s: On wait\n", MODNAME);
		ret = wait_for_completion_interruptible(&result.completion);
		break;
	default:
		pr_info("%s: DEFAULT\n", MODNAME);
	}

error_req:
	ablkcipher_request_free(req);
error_tfm:
	crypto_free_ablkcipher(tfm);
	return ret;
}

#define NB_SG 256
struct sglist {
	struct scatterlist *s;
	void *suf[NB_SG];
};

/* allocate nb SG of 4096bytes each with content set to pat */
static int allocate_sglist(struct sglist *sgl, unsigned int nb,
			   unsigned char pat)
{
	int i, err;

	if (nb == 0 || nb > NB_SG) {
		pr_err("%s Invalid arg\n", MODNAME);
		return -EINVAL;
	}

	pr_info("%s: SGI CREATE %d\n", MODNAME, nb);
	sgl->s = kcalloc(nb, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sgl->s) {
		pr_err("%s ERROR: Cannot allocate sgil\n", MODNAME);
		return -ENOMEM;
	}

	sg_init_table(sgl->s, nb);
	for (i = 0; i < nb; i++)
		sgl->suf[i] = NULL;
	for (i = 0; i < nb; i++) {
		sgl->suf[i] = kmalloc(4096, GFP_KERNEL);
		if (!sgl->suf[i]) {
			pr_err("%s ERROR: Cannot allocate buf %u\n",
			       MODNAME, i);
			err = -ENOMEM;
			goto error_sgil;
		}
		memset(sgl->suf[i], pat, 4096);
		sg_set_buf(&sgl->s[i], sgl->suf[i], 4096);
	}

	return 0;
error_sgil:
	for (i = 0; i < nb; i++)
		kfree(sgl->suf[i]);
	kfree(sgl->s);
	return err;
}

/* Compare the content of two SGs */
static int cryptotest_comp_sgs(struct scatterlist *r, struct scatterlist *t,
			       unsigned int size)
{
	struct sg_mapping_iter mr, mt;
	unsigned int todo;
	unsigned int remain = size;
	int err = 0;
	unsigned int or, ot, i;

	sg_miter_start(&mr, r, sg_nents_for_len(r, size), SG_MITER_FROM_SG);
	sg_miter_start(&mt, t, sg_nents_for_len(t, size), SG_MITER_FROM_SG);
	or = 0;
	ot = 0;
	sg_miter_next(&mr);
	sg_miter_next(&mt);
	while (remain > 0) {
		todo = min3(mr.length - or, mt.length - ot, remain);
		pr_debug("%s %s: proceed %u (%u/%zu %u/%zu %u) sgs=%d/%d\n",
			 MODNAME, __func__,
			 todo, or, mr.length, ot, mt.length, remain,
			 sg_nents_for_len(r, size),
			 sg_nents_for_len(t, size));
		err = memcmp(mr.addr + or, mt.addr + ot, todo);
		if (err != 0) {
			for (i = 0; i < todo; i++) {
				if (*(u8 *)(mr.addr + or + i) != *(u8 *)(mt.addr + ot + i))
					break;
			}
			pr_err("%s: compare error %d at %u\n", MODNAME, err, i);
			if (todo - i > 8)
				todo = i + 8;
			if (i > 8)
				i -= 8;
			else
				i = 0;
			for (i = 0; i < todo; i++) {
				pr_info("%s %02d %u %u %02x %02x\n", MODNAME, i,
					or, ot,
					*(u8 *)(mr.addr + or + i),
					*(u8 *)(mt.addr + ot + i));
			}
			goto comp_end;
		}
		remain -= todo;
		or += todo;
		ot += todo;
		if (or >= mr.length && remain > 0) {
			sg_miter_next(&mr);
			or = 0;
			pr_debug("%s: next mr %zu at %p\n", MODNAME, mr.length,
				 mr.addr);
		}
		if (ot >= mt.length && remain > 0) {
			sg_miter_next(&mt);
			ot = 0;
			pr_debug("%s: next mt %zu at %p\n", MODNAME, mt.length,
				 mt.addr);
		}
	}
comp_end:
	sg_miter_stop(&mr);
	sg_miter_stop(&mt);
	return err;
}

static int __init cryptotest_init(void)
{
	/*struct scatterlist *sgil = NULL;*/
	int result = 0;
	int i, err;
	const char iv1[] = "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30"
		"\xb4\x22\xda\x80\x2c\x9f\xac\x41";
	const unsigned char key1[] = "\x06\xa9\x21\x40\x36\xb8\xa1"
		"\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06";
/*	const char data1[] = "Single block msg";*/
	char iv[16];
	/*	ktime_t t_start;
		ktime_t t_end;
		u32 nbrequest = 5000;*/
/*	void *suf[NB_SG];*/
#ifdef TEST_HASH
	u8 gresult[128];
	u8 hresult[128];
	int bench_adv = 0;
	int bench_update = 0;
#endif
	/*struct sg_mapping_iter m;
	u8 *tmp8;*/
	unsigned int data_len;
	struct sglist *sgd = NULL; /* plaintext */
	struct sglist *sgr = NULL; /* ciphered by generic cipher */
	struct sglist *sgt = NULL; /* ciphered by tested cipher */
	struct sglist *sgtd = NULL; /* de-ciphered by tested cipher */

	sgd = kzalloc(sizeof(*sgd), GFP_KERNEL);
	if (!sgd) {
		err = -ENOMEM;
		goto error_sgil;
	}
	sgr = kzalloc(sizeof(*sgr), GFP_KERNEL);
	if (!sgr) {
		err = -ENOMEM;
		goto error_sgil;
	}
	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt) {
		err = -ENOMEM;
		goto error_sgil;
	}
	sgtd = kzalloc(sizeof(*sgtd), GFP_KERNEL);
	if (!sgtd) {
		err = -ENOMEM;
		goto error_sgil;
	}

	err = allocate_sglist(sgd, NB_SG, 0x11);
	if (err != 0)
		goto error_sgil;
	err = allocate_sglist(sgr, NB_SG, 0x22);
	if (err != 0)
		goto error_sgil;
	err = allocate_sglist(sgt, NB_SG, 0x33);
	if (err != 0)
		goto error_sgil;
	err = allocate_sglist(sgtd, NB_SG, 0x44);
	if (err != 0)
		goto error_sgil;
#define TEST_CIPHER
#ifdef TEST_CIPHER

	for (data_len = 16; data_len <= 8192 * 16; data_len += 16) {
		pr_debug("%s: Testing cipher size=%d\n", MODNAME, data_len);

		/* init source data */
		/*
		sg_miter_start(&m, &sgil[0], sg_nents(&sgil[0]),
			       SG_MITER_TO_SG);
		sg_miter_next(&m);
		tmp8 = m.addr;
		for (i = 0; i < 16; i++) {
			tmp8[i] = data1[i];
			pr_debug("%02d %02x %c %p %p\n", i, tmp8[i], tmp8[i],
				 m.addr + i, suf[i]);
		}

		sg_miter_stop(&m);*/

		/* TODO : compare IV at end */
		for (i = 0; i < 16; i++)
			iv[i] = iv1[i];
		err = do_test_cipher("cbc(aes-generic)", iv, key1, 16,
				     sgd->s, sgr->s, data_len, 0);
		if (err) {
			pr_err("%s ERROR: do_test_cipher %d\n", MODNAME, err);
			goto test_cipher_end;
		}

		for (i = 0; i < 16; i++)
			iv[i] = iv1[i];
		/*err = do_test_cipher("cbc-aes-sun4i-ss", iv, key1, 16,*/
		err = do_test_cipher("cbc(aes)", iv, key1, 16,
				     sgd->s, sgt->s, data_len, 0);
		if (err) {
			pr_err("%s ERROR: do_test_cipher %d\n", MODNAME, err);
			goto test_cipher_end;
		}

		err = cryptotest_comp_sgs(sgr->s, sgt->s, data_len);
		if (err)
			goto test_cipher_end;
		/* now decipher */
		for (i = 0; i < 16; i++)
			iv[i] = iv1[i];
		err = do_test_cipher("cbc(aes)", iv, key1, 16,
				     sgt->s, sgtd->s, data_len, 1);
		if (err) {
			pr_err("%s ERROR: do_test_cipher %d\n", MODNAME, err);
			goto test_cipher_end;
		}

		err = cryptotest_comp_sgs(sgd->s, sgtd->s, data_len);
		if (err)
			goto test_cipher_end;
	}
	pr_info("%s: test_cipher End\n", MODNAME);
test_cipher_end:
#endif /* TEST_CIPHER*/

#ifdef TEST_HASH
	for (bench_update = 0; bench_update < 120; bench_update++) {
		pr_info("%s: test_hash update=%d\n", MODNAME, bench_update);
		for (bench_adv = 0; bench_adv < NB_SG - 1; bench_adv++) {
			err = do_hash_test("md5-generic", hresult, bench_adv, sgd->s,
				      bench_update);
			if (err != 0)
				goto error_sgil;
			/* copy the result in our reference result */
			for (i = 0; i < MD5_DIGEST_SIZE; i++)
				gresult[i] = hresult[i];
			err = do_hash_test("md5", hresult, bench_adv, sgd->s,
				      bench_update);
			if (err != 0)
				goto error_sgil;
			for (i = 0; i < MD5_DIGEST_SIZE; i++)
				if (gresult[i] != hresult[i]) {
					pr_err("%s: ERROR: md5 problem %d %d i=%d %02x vs %02x\n",
					       MODNAME, bench_adv,
					       bench_update, i, gresult[i],
					       hresult[i]);
					i = MD5_DIGEST_SIZE;
					bench_update = 128;
					bench_adv = NB_SG;
				}
		}

		for (bench_adv = 0; bench_adv < NB_SG - 1; bench_adv++) {
			do_hash_test("sha1-generic", hresult, bench_adv, sgd->s,
				bench_update);
			for (i = 0; i < SHA1_DIGEST_SIZE; i++)
				gresult[i] = hresult[i];
			do_hash_test("sha1", hresult, bench_adv, sgd->s, bench_update);
			for (i = 0; i < SHA1_DIGEST_SIZE; i++)
				if (gresult[i] != hresult[i]) {
					pr_err("%s ERROR: sha1 problem %d %d i=%d %02x vs %02x\n",
					       MODNAME, bench_adv,
					       bench_update, i, gresult[i],
					       hresult[i]);
					i = SHA1_DIGEST_SIZE;
					bench_update = 128;
					bench_adv = NB_SG;
				}
		}
	}
#endif /* TEST_HASH */

error_sgil:
	for (i = 0; i < NB_SG; i++) {
		if (sgd)
			kfree(sgd->suf[i]);
		if (sgr)
			kfree(sgr->suf[i]);
		if (sgt)
			kfree(sgt->suf[i]);
		if (sgtd)
			kfree(sgtd->suf[i]);
	}
	kfree(sgd);
	kfree(sgr);
	kfree(sgt);
	kfree(sgtd);
	return result;
}

static void __exit cryptotest_exit(void)
{
}

module_init(cryptotest_init);
module_exit(cryptotest_exit);

MODULE_AUTHOR("Corentin LABBE <clabbe.montjoie@gmail.com>");
MODULE_DESCRIPTION("test and bench encryption / decryption");
MODULE_LICENSE("GPL");
