/*
 * Copyright (C) 2016 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "credentials/cred_encoding.h"
#include "credentials/keys/private_key.h"
#include "credentials/keys/public_key.h"
#include "test_suite.h"
#include "utils/chunk.h"

#include <time.h>

typedef struct sig_test_t sig_test_t;

struct sig_test_t {
	chunk_t key;
	chunk_t pubkey;
	chunk_t msg;
	chunk_t fp_pk;
	chunk_t fp_spki;
};

/**
 * SM2 Test Vectors from RFC XXXX
 */
static sig_test_t sig_tests[] = {
	/* Test 1 */
	{
		chunk_from_chars(
		0x30, 0x81, 0x93, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07,
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
		0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, 0x04, 0x79, 0x30,
		0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x04, 0xD4, 0xBA, 0x33,
		0xCF, 0x12, 0xA5, 0x51, 0x2C, 0xDA, 0x2F, 0x61, 0x7D, 0xAE,
		0xDD, 0xF7, 0x2C, 0x39, 0x22, 0xA3, 0x9D, 0x22, 0x50, 0xAE,
		0xA6, 0x00, 0x0F, 0xAB, 0x05, 0xCE, 0x9F, 0x3E, 0xA0, 0x0A,
		0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D,
		0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x2B, 0xA0, 0xCF, 0x3E,
		0x61, 0x88, 0x49, 0x19, 0x0B, 0x83, 0x02, 0x47, 0xFC, 0x29,
		0x2F, 0x66, 0x5E, 0x8A, 0xCA, 0x7D, 0x3C, 0xC2, 0x48, 0xEB,
		0xF7, 0x91, 0xB5, 0xB0, 0xCB, 0x31, 0x5E, 0x54, 0xDF, 0x15,
		0x3A, 0x03, 0x3F, 0x83, 0x93, 0xD0, 0xEB, 0x0E, 0xBC, 0x24,
		0xC4, 0x46, 0xCB, 0x3A, 0x74, 0x96, 0x78, 0x6A, 0x81, 0xA0,
		0x14, 0x8F, 0x1A, 0x0E, 0x98, 0x10, 0xBA, 0xC6, 0xB4, 0xA3
		),
		chunk_from_chars(
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
		0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55,
		0x01, 0x82, 0x2D, 0x03, 0x42, 0x00, 0x04, 0x2B, 0xA0, 0xCF,
		0x3E, 0x61, 0x88, 0x49, 0x19, 0x0B, 0x83, 0x02, 0x47, 0xFC,
		0x29, 0x2F, 0x66, 0x5E, 0x8A, 0xCA, 0x7D, 0x3C, 0xC2, 0x48,
		0xEB, 0xF7, 0x91, 0xB5, 0xB0, 0xCB, 0x31, 0x5E, 0x54, 0xDF,
		0x15, 0x3A, 0x03, 0x3F, 0x83, 0x93, 0xD0, 0xEB, 0x0E, 0xBC,
		0x24, 0xC4, 0x46, 0xCB, 0x3A, 0x74, 0x96, 0x78, 0x6A, 0x81,
		0xA0, 0x14, 0x8F, 0x1A, 0x0E, 0x98, 0x10, 0xBA, 0xC6, 0xB4,
		0xA3
		),
		{ "sm2", 3
		},
		chunk_from_chars(
		0xDD, 0x81, 0x53, 0x03, 0x5F, 0x81, 0x2B, 0xEC, 0x32, 0x01,
		0x5B, 0x26, 0x8A, 0x80, 0x96, 0xFC, 0x05, 0xD3, 0x80, 0x7B,
		0xD2, 0xE8, 0xA4, 0x48, 0x95, 0xAF, 0x19, 0xF9, 0x14, 0x67,
		0x7B, 0x25
		),
		chunk_from_chars(
		0x6E, 0xBD, 0x57, 0x38, 0x1E, 0x05, 0x69, 0xB6, 0x7B, 0x56,
		0xFE, 0x5A, 0x43, 0x3E, 0xC7, 0xCD, 0xBD, 0x4E, 0xAE, 0xDB,
		0xE4, 0x0A, 0x74, 0xA9, 0x88, 0xE5, 0x2D, 0x09, 0x92, 0xC5,
		0x95, 0x8C
		),
	},
};

START_TEST(test_sm2_sign)
{
	private_key_t *key;
	public_key_t *pubkey, *public;
	chunk_t sig, encoding, fp;

	/* load private key */
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, sig_tests[_i].key, BUILD_END);
	ck_assert(key != NULL);
	ck_assert(key->get_encoding(key, PRIVKEY_ASN1_DER, &encoding));
	ck_assert_chunk_eq(encoding, sig_tests[_i].key);
	chunk_free(&encoding);

	ck_assert(key->get_fingerprint(key, KEYID_PUBKEY_SM3, &fp));
	ck_assert_chunk_eq(sig_tests[_i].fp_pk, fp);
	ck_assert(key->get_fingerprint(key, KEYID_PUBKEY_INFO_SM3, &fp));
	ck_assert_chunk_eq(sig_tests[_i].fp_spki, fp);

	/* load public key */
	pubkey = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, sig_tests[_i].pubkey, BUILD_END);
	ck_assert(pubkey != NULL);
	ck_assert(pubkey->get_encoding(pubkey, PUBKEY_SPKI_ASN1_DER, &encoding));
	ck_assert_chunk_eq(encoding, sig_tests[_i].pubkey);
	chunk_free(&encoding);

	ck_assert(pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_SM3, &fp));
	ck_assert_chunk_eq(sig_tests[_i].fp_pk, fp);
	ck_assert(pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_INFO_SM3, &fp));
	ck_assert_chunk_eq(sig_tests[_i].fp_spki, fp);

	/* compare public keys */
	public = key->get_public_key(key);
	ck_assert(public != NULL);
	ck_assert(public->equals(public, pubkey));

	/* sign */
	ck_assert(key->sign(key, SIGN_SM2_WITH_SM3, NULL, sig_tests[_i].msg, &sig));

	/* verify */
	ck_assert(pubkey->verify(pubkey, SIGN_SM2_WITH_SM3, NULL, sig_tests[_i].msg, sig));

	/* cleanup */
	key->destroy(key);
	pubkey->destroy(pubkey);
	public->destroy(public);
	chunk_free(&sig);
}
END_TEST

START_TEST(test_sm2_gen)
{
	private_key_t *key;
	private_key_t *key2;
	public_key_t *pubkey, *pubkey2;
	chunk_t msg = chunk_from_str("sm2"), sig, encoding, fp_priv, fp_pub;

	/* generate private key */
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2, BUILD_END);
	ck_assert(key != NULL);
	ck_assert(key->get_type(key) == KEY_SM2);
	ck_assert(key->get_keysize(key) == 256);

	/* clone private key */
	key2 = key->get_ref(key);
	ck_assert(key2);
	key2->destroy(key2);

	/* wrong signature scheme */
	ck_assert(!key->sign(key, SIGN_ED448, NULL, msg, &sig));

	/* correct signature scheme*/
	ck_assert(key->sign(key, SIGN_SM2_WITH_SM3, NULL, msg, &sig));
	/* export public key */
	pubkey = key->get_public_key(key);
	ck_assert(pubkey != NULL);
	ck_assert(pubkey->get_type(pubkey) == KEY_SM2);
	ck_assert(pubkey->get_keysize(pubkey) == 512);
	ck_assert(pubkey->get_encoding(pubkey, PUBKEY_PEM, &encoding));
	ck_assert(encoding.ptr != NULL);
	ck_assert(strstr(encoding.ptr, "PUBLIC KEY"));
	chunk_free(&encoding);

	/* generate and compare public and private key fingerprints */
	ck_assert(!key->get_fingerprint(key, KEYID_PGPV4, &fp_priv));
	ck_assert(key->get_fingerprint(key, KEYID_PUBKEY_SM3, &fp_priv));
	ck_assert(key->get_fingerprint(key, KEYID_PUBKEY_SM3, &fp_priv));
	ck_assert(fp_priv.ptr != NULL);
	ck_assert(!pubkey->get_fingerprint(pubkey, KEYID_PGPV4, &fp_pub));
	ck_assert(pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_SM3, &fp_pub));
	ck_assert(pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_SM3, &fp_pub));
	ck_assert(fp_pub.ptr != NULL);
	// ck_assert_chunk_eq(fp_pub, fp_priv);

	/* clone public key */
	pubkey2 = pubkey->get_ref(pubkey);
	ck_assert(pubkey2 != NULL);
	pubkey2->destroy(pubkey2);

	/* verify with wrong signature scheme */
	ck_assert(!pubkey->verify(pubkey, SIGN_ED448, NULL, msg, sig));

	/* verify with correct signature scheme */
	ck_assert(pubkey->verify(pubkey, SIGN_SM2_WITH_SM3, NULL, msg, sig));

	/* cleanup */
	key->destroy(key);
	pubkey->destroy(pubkey);
	chunk_free(&sig);
}
END_TEST

START_TEST(test_sm2_fail)
{
	private_key_t *key;
	public_key_t *pubkey;
	chunk_t blob;

	/* Invalid private key format */
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, chunk_empty, BUILD_END);
	ck_assert(key == NULL);

	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2,
					BUILD_EDDSA_PRIV_ASN1_DER, chunk_empty, BUILD_END);
	ck_assert(key == NULL);

	blob = chunk_from_chars(0x04, 0x01, 0x9d);
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2,
					BUILD_EDDSA_PRIV_ASN1_DER, blob, BUILD_END);
	ck_assert(key == NULL);

	/* Invalid public key format */
	pubkey = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, chunk_empty, BUILD_END);
	ck_assert(pubkey == NULL);

	blob = chunk_from_chars(0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
							0x70, 0x03, 0x02, 0x00, 0xd7);
	pubkey = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, blob, BUILD_END);
	ck_assert(pubkey == NULL);

	blob = chunk_from_chars(0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x00,
							0x70, 0x03, 0x02, 0x00, 0xd7);
	pubkey = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, blob, BUILD_END);
	ck_assert(pubkey == NULL);

	pubkey = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
					BUILD_KEY_SIZE, 512, BUILD_BLOB_ASN1_DER, blob, BUILD_END);
	ck_assert(pubkey == NULL);

	/* Invalid signature format */
	pubkey = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, sig_tests[0].pubkey, BUILD_END);
	ck_assert(pubkey != NULL);

	ck_assert(!pubkey->verify(pubkey, SIGN_SM2_WITH_SM3, NULL, chunk_empty,
							  chunk_empty));

	pubkey->destroy(pubkey);
}
END_TEST

#define SM2_MAX_PLAINTEXT_SIZE	255 // re-compute SM2_MAX_CIPHERTEXT_SIZE when modify
START_TEST(test_sm2_public_enc)
{
	private_key_t *key;
	public_key_t *public;
	chunk_t crypto, plain, decrypt;
	uint8_t plaintext[] = "Hello World!";

	/* load private key */
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2, BUILD_END);
	ck_assert(key != NULL);

	public = key->get_public_key(key);
	ck_assert(public != NULL);

	plain = chunk_create(plaintext, sizeof(plaintext));
	ck_assert(public->encrypt(public, 0, NULL, plain, &crypto) == TRUE);
	ck_assert(key->decrypt(key, 0, NULL, crypto, &decrypt) == TRUE);
	ck_assert(chunk_equals(decrypt, plain));

	chunk_free(&crypto);
	chunk_free(&decrypt);
}
END_TEST

Suite *sm2_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("sm2");

	tc = tcase_create("sm2_sign");
	tcase_add_loop_test(tc, test_sm2_sign, 0, countof(sig_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("sm2_gen");
	tcase_add_test(tc, test_sm2_gen);
	suite_add_tcase(s, tc);

	tc = tcase_create("sm2_fail");
	tcase_add_test(tc, test_sm2_fail);
	suite_add_tcase(s, tc);


	tc = tcase_create("sm2_public_enc");
	tcase_add_test(tc, test_sm2_public_enc);
	suite_add_tcase(s, tc);

	return s;
}
