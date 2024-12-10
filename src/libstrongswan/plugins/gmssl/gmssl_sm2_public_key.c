#include "gmssl_sm2_public_key.h"
#include "gmssl_util.h"

#include <gmssl/asn1.h>

typedef struct private_sm2_public_key_t private_sm2_public_key_t;

struct private_sm2_public_key_t {
    sm2_public_key_t public;
	SM2_POINT pubkey;
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_sm2_public_key_t *this)
{
	return KEY_SM2;
}

METHOD(public_key_t, verify, bool,
	private_sm2_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	int ret;
	SM2_SIGN_CTX sign_ctx;
	SM2_KEY sm2_key = {
		.public_key = this->pubkey,
	};

	if (scheme != SIGN_SM2_WITH_SM3)
		return FALSE;
	
	if (sm2_verify_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_verify_update(&sign_ctx, data.ptr, data.len) != 1
		|| (ret = sm2_verify_finish(&sign_ctx, signature.ptr, signature.len)) != 1) {
		return FALSE;
	}

	return ret == 1;
}

METHOD(public_key_t, encrypt, bool,
	private_sm2_public_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t plain, chunk_t *crypto)
{
	if (crypto == NULL)
		return FALSE;

	unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
	size_t len = 0;

	sm2_encrypt((const SM2_KEY *)&this->pubkey, plain.ptr, plain.len,
														ciphertext, &len);

	*crypto = chunk_alloc(len);
	memcpy(crypto->ptr, ciphertext, len);

	return TRUE;
}

METHOD(public_key_t, get_keysize, int,
	private_sm2_public_key_t *this)
{
	return 8 * 64;
}

METHOD(public_key_t, get_encoding, bool,
	private_sm2_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	bool success = TRUE;
	uint8_t point[SM2_POINT_MAX_SIZE];
	uint8_t buff[512];
	uint8_t *p;
	size_t len = 0;
	SM2_KEY key = {
		.public_key = this->pubkey,
	};

	switch (type)
	{
		case PUBKEY_ASN1_DER:
		case PUBKEY_PEM:
		{
			bool success = TRUE;
			p = point;
			len = 0;
			if (sm2_point_to_der(&key.public_key, &p, &len) != 1)
				return FALSE;

			*encoding = chunk_alloc(len);
			memcpy(encoding->ptr, point, len);

			if (type == PUBKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, type,
								NULL, encoding, CRED_PART_ECDSA_PUB_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}
			return success;
		}
		case PUBKEY_SPKI_ASN1_DER:
		{
			p = buff;
			len = 0;
			if (sm2_public_key_info_to_der(&key, &p, &len) != 1)
				return FALSE;
			*encoding = chunk_alloc(len);
			memcpy(encoding->ptr, buff, len);
			return success;
		}
		default:
			return FALSE;
	}

	return success;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_sm2_public_key_t *this, cred_encoding_type_t type,
	chunk_t *fp)
{
	SM2_KEY sm2_key = {
		.public_key = this->pubkey,
	};
	return sm2_public_key_fingerprint(&sm2_key, type, fp);
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_sm2_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_sm2_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		memset(&this->pubkey, 0, sizeof(this->pubkey));
		free(this);
	}
}

sm2_public_key_t *sm2_public_key_load(key_type_t type, va_list args)
{
	private_sm2_public_key_t *this;
	chunk_t chunk = chunk_empty;
	const uint8_t *p;
	size_t len;
	SM2_KEY key;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				chunk = va_arg(args, chunk_t);
				p = chunk.ptr;
				len = chunk.len;
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (sm2_public_key_info_from_der(&key, &p, &len) != 1 
		|| asn1_length_is_zero(len) != 1)
	{
		return FALSE;
	}

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt,
				.get_keysize = _get_keysize,
				.equals = public_key_equals,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
		.pubkey = key.public_key,
	);

	return &this->public;
}
