/*
 * Copyright (C) 2025
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

#include "qkd_types.h"

#include <asn1/asn1.h>

/**
 * Discriminator values for typed components in USE_QKD (SET).
 */
enum {
	QKD_ASN_USAGE = 1,
	QKD_ASN_MODE = 2,
	QKD_ASN_VENDOR = 3,
	QKD_ASN_VERSION = 4,
	QKD_ASN_CONFIG = 5,
	QKD_ASN_KEYID = 6,
	QKD_ASN_KEYLEN = 7,
	QKD_ASN_ENVELOPE = 8,
	QKD_ASN_STATUS = 9,
};

#define QKD_ASN_SET_MAX	9

void qkd_params_init(qkd_params_t *params)
{
	memset(params, 0, sizeof(*params));
}

void qkd_params_destroy(qkd_params_t *params)
{
	chunk_clear(&params->vendor);
	chunk_clear(&params->version);
	chunk_clear(&params->config);
	chunk_clear(&params->keyid);
	chunk_clear(&params->envelope);
	qkd_params_init(params);
}

bool qkd_params_clone(qkd_params_t *dst, qkd_params_t *src)
{
	qkd_params_init(dst);
	dst->usage = src->usage;
	dst->mode = src->mode;
	dst->keylen = src->keylen;
	dst->status = src->status;
	dst->has_status = src->has_status;
	dst->vendor = chunk_clone(src->vendor);
	dst->version = chunk_clone(src->version);
	dst->config = chunk_clone(src->config);
	dst->keyid = chunk_clone(src->keyid);
	dst->envelope = chunk_clone(src->envelope);
	return TRUE;
}

/**
 * Build an ASN.1 ENUMERATED object.
 */
static chunk_t asn1_enumerated(uint64_t val)
{
	chunk_t content = asn1_integer_from_uint64(val);

	return asn1_simple_object(ASN1_ENUMERATED, content);
}

/**
 * Build an ASN.1 OCTET STRING object (copies data).
 */
static chunk_t asn1_octet_string(chunk_t data)
{
	return asn1_simple_object(ASN1_OCTET_STRING, chunk_clone(data));
}

/**
 * Wrap { type INTEGER, length INTEGER, value } as SEQUENCE.
 */
static chunk_t build_typed_component(uint64_t type, chunk_t value)
{
	chunk_t type_tlv, len_tlv;

	type_tlv = asn1_simple_object(ASN1_INTEGER, asn1_integer_from_uint64(type));
	len_tlv = asn1_simple_object(ASN1_INTEGER,
								  asn1_integer_from_uint64(value.len));
	return asn1_wrap(ASN1_SEQUENCE, "mmm", type_tlv, len_tlv, value);
}

/**
 * Compare two DER objects for canonical SET ordering.
 */
static int compare_der(const void *a, const void *b)
{
	const chunk_t *ca = a, *cb = b;
	size_t len;
	int diff;

	len = min(ca->len, cb->len);
	diff = memcmp(ca->ptr, cb->ptr, len);
	if (diff)
	{
		return diff;
	}
	if (ca->len < cb->len)
	{
		return -1;
	}
	if (ca->len > cb->len)
	{
		return 1;
	}
	return 0;
}

/**
 * Build a DER SET from sorted member encodings.
 */
static chunk_t build_set(chunk_t *members, int count)
{
	chunk_t set = chunk_empty;
	u_char *pos;
	size_t len = 0;
	int i;

	if (!count)
	{
		return asn1_wrap(ASN1_SET, "");
	}
	for (i = 0; i < count; i++)
	{
		len += members[i].len;
	}
	pos = asn1_build_object(&set, ASN1_SET, len);
	for (i = 0; i < count; i++)
	{
		memcpy(pos, members[i].ptr, members[i].len);
		pos += members[i].len;
	}
	return set;
}

static bool assign_octet(chunk_t *field, chunk_t object, asn1_t type)
{
	chunk_t content;
	int tag;

	tag = asn1_unwrap(&object, &content);
	if (tag != type)
	{
		return FALSE;
	}
	chunk_clear(field);
	*field = chunk_clone(content);
	return TRUE;
}

static bool parse_typed_component(chunk_t seq_body, qkd_params_t *params)
{
	chunk_t object, value;
	uint64_t type, length;
	int tag;

	/* seq_body is already the body of one SET member (Usage/Mode/... SEQUENCE),
	 * asn1_unwrap() at the caller stripped the outer 0x30 tag+length */
	value = seq_body;
	tag = asn1_unwrap(&value, &object);
	if (tag != ASN1_INTEGER)
	{
		return FALSE;
	}
	type = asn1_parse_integer_uint64(object);
	tag = asn1_unwrap(&value, &object);
	if (tag != ASN1_INTEGER)
	{
		return FALSE;
	}
	length = asn1_parse_integer_uint64(object);
	if (value.len != length)
	{
		return FALSE;
	}

	switch (type)
	{
		case QKD_ASN_USAGE:
		{
			uint64_t usage;

			tag = asn1_unwrap(&value, &object);
			if (tag != ASN1_ENUMERATED)
			{
				return FALSE;
			}
			usage = asn1_parse_integer_uint64(object);
			if (usage != QKD_REQUIRED && usage != QKD_PREFERRED)
			{
				return FALSE;
			}
			params->usage = usage;
			break;
		}
		case QKD_ASN_MODE:
		{
			uint64_t mode;

			tag = asn1_unwrap(&value, &object);
			if (tag != ASN1_ENUMERATED)
			{
				return FALSE;
			}
			mode = asn1_parse_integer_uint64(object);
			if (mode != QKD_MODE_PRF && mode != QKD_MODE_XOR)
			{
				return FALSE;
			}
			params->mode = mode;
			break;
		}
		case QKD_ASN_VENDOR:
			return assign_octet(&params->vendor, value, ASN1_OCTET_STRING);
		case QKD_ASN_VERSION:
			return assign_octet(&params->version, value, ASN1_OCTET_STRING);
		case QKD_ASN_CONFIG:
			return assign_octet(&params->config, value, ASN1_OCTET_STRING);
		case QKD_ASN_KEYID:
			return assign_octet(&params->keyid, value, ASN1_OCTET_STRING);
		case QKD_ASN_ENVELOPE:
			return assign_octet(&params->envelope, value, ASN1_OCTET_STRING);
		case QKD_ASN_KEYLEN:
		{
			uint64_t keylen;

			tag = asn1_unwrap(&value, &object);
			if (tag != ASN1_INTEGER)
			{
				return FALSE;
			}
			keylen = asn1_parse_integer_uint64(object);
			params->keylen = keylen;
			break;
		}
		case QKD_ASN_STATUS:
		{
			uint64_t status;

			tag = asn1_unwrap(&value, &object);
			if (tag != ASN1_INTEGER)
			{
				return FALSE;
			}
			status = asn1_parse_integer_uint64(object);
			params->status = status;
			params->has_status = TRUE;
			break;
		}
		default:
			return FALSE;
	}
	return value.len == 0;
}

static bool parse_use_qkd(chunk_t blob, qkd_params_t *params)
{
	chunk_t set, member;
	int tag;

	if (!is_asn1(blob))
	{
		return FALSE;
	}
	tag = asn1_unwrap(&blob, &set);
	if (tag != ASN1_SET || blob.len)
	{
		return FALSE;
	}
	while (set.len)
	{
		tag = asn1_unwrap(&set, &member);
		if (tag != ASN1_SEQUENCE || !parse_typed_component(member, params))
		{
			return FALSE;
		}
	}
	return TRUE;
}

chunk_t qkd_params_encode(qkd_params_t *params)
{
	chunk_t members[QKD_ASN_SET_MAX];
	int count = 0;
	chunk_t value;

	if (params->usage)
	{
		value = asn1_enumerated(params->usage);
		members[count++] = build_typed_component(QKD_ASN_USAGE, value);
	}
	if (params->mode)
	{
		value = asn1_enumerated(params->mode);
		members[count++] = build_typed_component(QKD_ASN_MODE, value);
	}
	if (params->vendor.len)
	{
		value = asn1_octet_string(params->vendor);
		members[count++] = build_typed_component(QKD_ASN_VENDOR, value);
	}
	if (params->version.len)
	{
		value = asn1_octet_string(params->version);
		members[count++] = build_typed_component(QKD_ASN_VERSION, value);
	}
	if (params->config.len)
	{
		value = asn1_octet_string(params->config);
		members[count++] = build_typed_component(QKD_ASN_CONFIG, value);
	}
	if (params->keyid.len)
	{
		value = asn1_octet_string(params->keyid);
		members[count++] = build_typed_component(QKD_ASN_KEYID, value);
	}
	if (params->keylen)
	{
		value = asn1_simple_object(ASN1_INTEGER,
						asn1_integer_from_uint64(params->keylen));
		members[count++] = build_typed_component(QKD_ASN_KEYLEN, value);
	}
	if (params->envelope.len)
	{
		value = asn1_octet_string(params->envelope);
		members[count++] = build_typed_component(QKD_ASN_ENVELOPE, value);
	}
	if (params->has_status)
	{
		value = asn1_simple_object(ASN1_INTEGER,
						asn1_integer_from_uint64(params->status));
		members[count++] = build_typed_component(QKD_ASN_STATUS, value);
	}
	if (count > 1)
	{
		qsort(members, count, sizeof(chunk_t), compare_der);
	}
	{
		chunk_t encoded = build_set(members, count);
		int i;

		for (i = 0; i < count; i++)
		{
			chunk_free(&members[i]);
		}
		return encoded;
	}
}

bool qkd_params_decode(chunk_t data, qkd_params_t *params)
{
	qkd_params_init(params);

	if (!data.len)
	{
		return FALSE;
	}
	if (!parse_use_qkd(data, params))
	{
		qkd_params_destroy(params);
		return FALSE;
	}
	return TRUE;
}
