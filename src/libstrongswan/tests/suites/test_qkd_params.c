/*
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#include "test_suite.h"

#include <asn1/asn1.h>
#include <qkd/qkd_types.h>

static bool chunk_equal(chunk_t a, chunk_t b)
{
	if (!a.len && !b.len)
	{
		return TRUE;
	}
	return chunk_equals(a, b);
}

static bool params_equal(qkd_params_t *a, qkd_params_t *b)
{
	return a->usage == b->usage &&
		   a->mode == b->mode &&
		   a->keylen == b->keylen &&
		   a->has_status == b->has_status &&
		   a->status == b->status &&
		   chunk_equal(a->vendor, b->vendor) &&
		   chunk_equal(a->version, b->version) &&
		   chunk_equal(a->config, b->config) &&
		   chunk_equal(a->keyid, b->keyid) &&
		   chunk_equal(a->envelope, b->envelope);
}

START_TEST(test_qkd_params_encode_empty)
{
	qkd_params_t params;
	chunk_t encoded;

	qkd_params_init(&params);
	encoded = qkd_params_encode(&params);
	ck_assert(encoded.len == 2);
	ck_assert(encoded.ptr[0] == ASN1_SET);
	ck_assert(encoded.ptr[1] == 0x00);
	ck_assert(is_asn1(encoded));
	chunk_free(&encoded);
}
END_TEST

START_TEST(test_qkd_params_decode_rejects_empty)
{
	qkd_params_t params;

	qkd_params_init(&params);
	ck_assert(!qkd_params_decode(chunk_empty, &params));
}
END_TEST

START_TEST(test_qkd_params_decode_rejects_invalid)
{
	qkd_params_t params;
	chunk_t garbage = chunk_from_str("not-asn1");

	qkd_params_init(&params);
	ck_assert(!qkd_params_decode(garbage, &params));
}
END_TEST

START_TEST(test_qkd_params_roundtrip)
{
	qkd_params_t orig, decoded;
	chunk_t encoded;

	qkd_params_init(&orig);
	orig.usage = QKD_REQUIRED;
	orig.mode = QKD_MODE_PRF;
	orig.keylen = 256;
	orig.status = 0;
	orig.vendor = chunk_clone(chunk_from_str("vendor_a"));
	orig.version = chunk_clone(chunk_from_str("1.0"));
	orig.config = chunk_clone(chunk_from_str("cfg"));
	orig.keyid = chunk_clone(chunk_from_str("key-42"));
	orig.envelope = chunk_clone(chunk_from_str("envelope"));

	encoded = qkd_params_encode(&orig);
	ck_assert(encoded.len > 2);
	ck_assert(is_asn1(encoded));
	ck_assert(encoded.ptr[0] == ASN1_SET);

	ck_assert(qkd_params_decode(encoded, &decoded));
	ck_assert(params_equal(&orig, &decoded));

	chunk_free(&encoded);
	qkd_params_destroy(&orig);
	qkd_params_destroy(&decoded);
}
END_TEST

START_TEST(test_qkd_params_roundtrip_minimal)
{
	qkd_params_t orig, decoded;
	chunk_t encoded;

	qkd_params_init(&orig);
	orig.usage = QKD_PREFERRED;
	orig.mode = QKD_MODE_XOR;

	encoded = qkd_params_encode(&orig);
	ck_assert(qkd_params_decode(encoded, &decoded));
	ck_assert(params_equal(&orig, &decoded));

	chunk_free(&encoded);
	qkd_params_destroy(&orig);
	qkd_params_destroy(&decoded);
}
END_TEST

START_TEST(test_qkd_params_clone)
{
	qkd_params_t orig, clone;

	qkd_params_init(&orig);
	orig.usage = QKD_REQUIRED;
	orig.vendor = chunk_clone(chunk_from_str("v"));

	ck_assert(qkd_params_clone(&clone, &orig));
	ck_assert(params_equal(&orig, &clone));
	ck_assert(clone.vendor.ptr != orig.vendor.ptr);

	qkd_params_destroy(&orig);
	qkd_params_destroy(&clone);
}
END_TEST

START_TEST(test_qkd_params_USE_QKD_i)
{
	qkd_params_t orig, decoded;
	chunk_t encoded;

	qkd_params_init(&orig);
	orig.usage = QKD_REQUIRED;
	orig.mode = QKD_MODE_PRF;
	orig.vendor = chunk_clone(chunk_from_str("vendor_a"));
	orig.version = chunk_clone(chunk_from_str("1.0"));

	encoded = qkd_params_encode(&orig);
	ck_assert(qkd_params_decode(encoded, &decoded));
	ck_assert(decoded.usage == orig.usage);
	ck_assert(decoded.mode == orig.mode);
	ck_assert(chunk_equals(decoded.vendor, orig.vendor));
	ck_assert(chunk_equals(decoded.version, orig.version));
	ck_assert(decoded.config.len == 0);
	ck_assert(decoded.keyid.len == 0);
	ck_assert(decoded.keylen == 0);
	ck_assert(decoded.envelope.len == 0);
	ck_assert(!decoded.has_status);

	chunk_free(&encoded);
	qkd_params_destroy(&orig);
	qkd_params_destroy(&decoded);
}
END_TEST

START_TEST(test_qkd_params_USE_QKD_r)
{
	qkd_params_t orig, decoded;
	chunk_t encoded;

	qkd_params_init(&orig);
	orig.usage = QKD_REQUIRED;
	orig.mode = QKD_MODE_PRF;
	orig.vendor = chunk_clone(chunk_from_str("vendor_a"));
	orig.version = chunk_clone(chunk_from_str("1.0"));
	orig.config = chunk_clone(chunk_from_str("custom config"));
	orig.keyid = chunk_clone(chunk_from_str("key id"));
	orig.keylen = orig.keyid.len;
	orig.envelope = chunk_clone(chunk_from_str("envelope"));
	orig.has_status = TRUE;
	orig.status = 0;

	encoded = qkd_params_encode(&orig);
	ck_assert(qkd_params_decode(encoded, &decoded));
	ck_assert(decoded.usage == orig.usage);
	ck_assert(decoded.mode == orig.mode);
	ck_assert(chunk_equals(decoded.vendor, orig.vendor));
	ck_assert(chunk_equals(decoded.version, orig.version));
	ck_assert(chunk_equals(decoded.config, orig.config));
	ck_assert(chunk_equals(decoded.keyid, orig.keyid));
	ck_assert(chunk_equals(decoded.envelope, orig.envelope));
	ck_assert(decoded.keylen == orig.keyid.len);
	ck_assert(decoded.has_status);
	ck_assert(decoded.status == orig.status);

	chunk_free(&encoded);
	qkd_params_destroy(&orig);
	qkd_params_destroy(&decoded);
}
END_TEST

START_TEST(test_qkd_params_USE_QKD_s)
{
	qkd_params_t orig, decoded;
	chunk_t encoded;

	qkd_params_init(&orig);
	orig.has_status = TRUE;
	orig.status = 0;

	encoded = qkd_params_encode(&orig);
	ck_assert(qkd_params_decode(encoded, &decoded));
	ck_assert(orig.has_status == decoded.has_status);
	ck_assert(orig.status == decoded.status);

	ck_assert(orig.usage == decoded.usage);
	ck_assert(orig.mode == decoded.mode);
	ck_assert(orig.vendor.len == 0);
	ck_assert(orig.version.len == 0);
	ck_assert(orig.config.len == 0);
	ck_assert(orig.keyid.len == 0);
	ck_assert(orig.envelope.len == 0);
	ck_assert(orig.keylen == decoded.keylen);

	chunk_free(&encoded);
	qkd_params_destroy(&orig);
	qkd_params_destroy(&decoded);
}
END_TEST

Suite *qkd_params_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("qkd_params");

	tc = tcase_create("encode");
	tcase_add_test(tc, test_qkd_params_encode_empty);
	suite_add_tcase(s, tc);

	tc = tcase_create("decode");
	tcase_add_test(tc, test_qkd_params_decode_rejects_empty);
	tcase_add_test(tc, test_qkd_params_decode_rejects_invalid);
	suite_add_tcase(s, tc);

	tc = tcase_create("roundtrip");
	tcase_add_test(tc, test_qkd_params_roundtrip);
	tcase_add_test(tc, test_qkd_params_roundtrip_minimal);
	suite_add_tcase(s, tc);

	tc = tcase_create("clone");
	tcase_add_test(tc, test_qkd_params_clone);
	suite_add_tcase(s, tc);

	tc = tcase_create("USE_QKD");
	tcase_add_test(tc, test_qkd_params_USE_QKD_i);
	tcase_add_test(tc, test_qkd_params_USE_QKD_r);
	tcase_add_test(tc, test_qkd_params_USE_QKD_s);
	suite_add_tcase(s, tc);


	return s;
}
