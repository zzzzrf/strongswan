#include <gmssl/sm2.h>
#include "gmssl/asn1.h"

#include "gmssl_sm2_private_key.h"
#include "gmssl_sm2_public_key.h"
#include "gmssl_util.h"

typedef struct private_sm2_private_key_t private_sm2_private_key_t;

struct private_sm2_private_key_t {
	sm2_private_key_t public;

	SM2_KEY key;
	SM2_POINT *pubkey;
	refcount_t ref;
};

METHOD(private_key_t, get_type, key_type_t,
	private_sm2_private_key_t *this)
{
	return KEY_SM2;
}

METHOD(private_key_t, sign, bool,
	private_sm2_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	if (scheme != SIGN_SM2_WITH_SM3)
		return FALSE;

	SM2_SIGN_CTX sign_ctx;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t len = 0;

	if (sm2_sign_init(&sign_ctx, &this->key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| sm2_sign_update(&sign_ctx, data.ptr, data.len) != 1
		|| sm2_sign_finish(&sign_ctx, sig, &len) != 1) {
		return FALSE;
	}

	*signature = chunk_alloc(len);
	memcpy(signature->ptr, sig, len);
	return TRUE;
}

METHOD(private_key_t, decrypt, bool,
	private_sm2_private_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	if (plain == NULL)
		return FALSE;

	unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
	size_t len = 0;

	if (sm2_decrypt(&this->key, crypto.ptr, crypto.len, plaintext, &len) != 1) {
		DBG1(DBG_LIB, "encryption scheme %N not supported", encryption_scheme_names, scheme);
		return FALSE;
	}

	*plain = chunk_alloc(len);
	memcpy(plain->ptr, plaintext, len);

	return TRUE;
}

METHOD(private_key_t, get_keysize, int,
	private_sm2_private_key_t *this)
{
	return 256;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_sm2_private_key_t *this)
{
	public_key_t *public;
	uint8_t buffer[512];
	uint8_t *p = buffer;
	size_t len = 0;

	if (sm2_public_key_info_to_der(&this->key, &p, &len) != 1)
		return NULL;

	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
								BUILD_BLOB_ASN1_DER, chunk_create(buffer, len), BUILD_END);
	return public;
}

METHOD(private_key_t, get_encoding, bool,
	private_sm2_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	uint8_t buf[SM2_PRIVATE_KEY_BUF_SIZE];;
	uint8_t *p = buf;
	size_t len = 0;

	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;

			if (sm2_private_key_info_to_der(&this->key, &p, &len) != 1) {
				return FALSE;
			}

			*encoding = chunk_alloc(len);
			memcpy(encoding->ptr, buf, len);
			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_ECDSA_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}
			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_fingerprint, bool,
	private_sm2_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fp)
{
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	success = sm2_public_key_fingerprint(&this->key, type, fp);
	if (success)
	{
		lib->encoding->cache(lib->encoding, type, this, fp);
	}
	return success;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_sm2_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_sm2_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		memset(&this->key, 0, sizeof(this->key));
		free(this);
	}
}

static private_sm2_private_key_t *create_internal(SM2_KEY *key)
{
	private_sm2_private_key_t *this;
	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.equals = private_key_equals,
				.belongs_to = private_key_belongs_to,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
		.key = *key,
	);
	this->pubkey = &this->key.public_key;
	return this;
}

sm2_private_key_t *sm2_private_key_gen(key_type_t type, va_list args)
{
	private_sm2_private_key_t *this;
	SM2_KEY key;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (sm2_key_generate(&key) != 1) {
		return NULL;
	}
	
	this = create_internal(&key);
	return &this->public;
}

sm2_private_key_t *sm2_private_key_load(key_type_t type, va_list args)
{
	private_sm2_private_key_t *this;
	SM2_KEY key;
	chunk_t blob = chunk_empty;
	const uint8_t *p = NULL;
	size_t len = 0;
	const uint8_t *attrs;
	size_t attrs_len;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				p = blob.ptr;
				len = blob.len;
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (sm2_private_key_info_from_der(&key, &attrs, &attrs_len, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		return NULL;
	}
	this = create_internal(&key);
	return &this->public;
}