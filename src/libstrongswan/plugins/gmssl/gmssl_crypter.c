
#include "gmssl_crypter.h"

#include <openssl/evp.h>

typedef struct private_gmssl_crypter_t private_gmssl_crypter_t;

/**
 * These are as defined by RFC 3686
 */
#define CTR_NONCE_LEN	4
#define CTR_IV_LEN		8

struct private_gmssl_crypter_t
{
    /**
	 * Public part of this class.
	 */
    gmssl_crypter_t public;

    /*
	 * The key
	 */
	chunk_t	key;

	/**
	 * Nonce value (CTR mode)
	 */
	chunk_t nonce;

	/*
	 * The cipher to use
	 */
	const EVP_CIPHER *cipher;

};

/**
 * Do the actual en/decryption in an EVP context
 */
static bool crypt(private_gmssl_crypter_t *this, chunk_t data, chunk_t iv,
				  chunk_t *dst, int enc)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	u_char iv_buf[EVP_CIPHER_iv_length(this->cipher)], *iv_ptr = iv_buf, *out;
	bool success = FALSE;

	if (this->nonce.len && (this->nonce.len + iv.len) <= sizeof(iv_buf))
	{
		memset(iv_buf, 0, sizeof(iv_buf));
		memcpy(iv_buf, this->nonce.ptr, this->nonce.len);
		memcpy(iv_buf + this->nonce.len, iv.ptr, iv.len);
		iv_buf[sizeof(iv_buf) - 1] = 1;
	}
	else if (iv.len == sizeof(iv_buf))
	{
		iv_ptr = iv.ptr;
	}
	else
	{
		return FALSE;
	}
	out = data.ptr;
	if (dst)
	{
		*dst = chunk_alloc(data.len);
		out = dst->ptr;
	}
	ctx = EVP_CIPHER_CTX_new();
	if (EVP_CipherInit_ex(ctx, this->cipher, NULL, NULL, NULL, enc) &&
		EVP_CIPHER_CTX_set_padding(ctx, 0) /* disable padding */ &&
		EVP_CIPHER_CTX_set_key_length(ctx, this->key.len) &&
		EVP_CipherInit_ex(ctx, NULL, NULL, this->key.ptr, iv_ptr, enc) &&
		EVP_CipherUpdate(ctx, out, &len, data.ptr, data.len) &&
		/* since padding is disabled this does nothing */
		EVP_CipherFinal_ex(ctx, out + len, &len))
	{
		success = TRUE;
	}
	EVP_CIPHER_CTX_free(ctx);
	return success;
}

METHOD(crypter_t, decrypt, bool,
	private_gmssl_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	return crypt(this, data, iv, dst, 0);
}

METHOD(crypter_t, encrypt, bool,
	private_gmssl_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	return crypt(this, data, iv, dst, 1);
}

METHOD(crypter_t, get_block_size, size_t,
	private_gmssl_crypter_t *this)
{
	return EVP_CIPHER_block_size(this->cipher);
}

METHOD(crypter_t, get_iv_size, size_t,
	private_gmssl_crypter_t *this)
{
	if (this->nonce.len)
	{
		return CTR_IV_LEN;
	}
	return EVP_CIPHER_iv_length(this->cipher);
}

METHOD(crypter_t, get_key_size, size_t,
	private_gmssl_crypter_t *this)
{
	return this->key.len + this->nonce.len;
}

METHOD(crypter_t, set_key, bool,
	private_gmssl_crypter_t *this, chunk_t key)
{
	if (key.len != get_key_size(this))
	{
		return FALSE;
	}
	memcpy(this->nonce.ptr, key.ptr + key.len - this->nonce.len, this->nonce.len);
	memcpy(this->key.ptr, key.ptr, this->key.len);
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	private_gmssl_crypter_t *this)
{
	chunk_clear(&this->key);
	chunk_clear(&this->nonce);
	free(this);
}

gmssl_crypter_t *gmssl_crypter_create(encryption_algorithm_t algo, size_t key_size)
{
    private_gmssl_crypter_t *this;
    size_t nonce_size = 0;

    INIT(this,
        .public = {
            .crypter = {
                .encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_iv_size = _get_iv_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
            },
        },
    );

    switch (algo)
    {
        case ENCR_SM4_CBC:
			switch (key_size)
			{
				case 0:
					key_size = 16;
				case 16:
					this->cipher = EVP_get_cipherbyname("sm4-cbc");
					break;
				default:
					free(this);
					return NULL;
			}
            break;
        default:
			break;
    }

    if (!this->cipher)
	{
		/* GmSSL does not support the requested algo */
		free(this);
		return NULL;
	}

    this->key = chunk_alloc(key_size);
	this->nonce = chunk_alloc(nonce_size);

	return &this->public;
}
