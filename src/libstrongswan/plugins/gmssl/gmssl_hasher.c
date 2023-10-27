#include "gmssl_hasher.h"
#include <openssl/evp.h>

typedef struct private_gmssl_hasher_t private_gmssl_hasher_t;

/**
 * Private data of gmssl_hasher_t
 */
struct private_gmssl_hasher_t
{
    /**
	 * Public part of this class.
	 */
	gmssl_hasher_t public;

	/**
	 * the hasher to use
	 */
	const EVP_MD *hasher;

	/**
	 * the current digest context
	 */
	EVP_MD_CTX *ctx;
};

METHOD(hasher_t, get_hash_size, size_t,
	private_gmssl_hasher_t *this)
{
	return EVP_MD_size(this->hasher);
}

METHOD(hasher_t, reset, bool,
	private_gmssl_hasher_t *this)
{
	return EVP_DigestInit_ex(this->ctx, this->hasher, NULL) == 1;
}

METHOD(hasher_t, get_hash, bool,
	private_gmssl_hasher_t *this, chunk_t chunk, uint8_t *hash)
{
	if (EVP_DigestUpdate(this->ctx, chunk.ptr, chunk.len) != 1)
	{
		return FALSE;
	}
	if (hash)
	{
		if (EVP_DigestFinal_ex(this->ctx, hash, NULL) != 1)
		{
			return FALSE;
		}
		return reset(this);
	}
	return TRUE;
}

METHOD(hasher_t, allocate_hash, bool,
	private_gmssl_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
	if (hash)
	{
		*hash = chunk_alloc(get_hash_size(this));
		return get_hash(this, chunk, hash->ptr);
	}
	return get_hash(this, chunk, NULL);
}

METHOD(hasher_t, destroy, void,
	private_gmssl_hasher_t *this)
{
	EVP_MD_CTX_destroy(this->ctx);
	free(this);
}

gmssl_hasher_t *gmssl_hasher_create(hash_algorithm_t algo)
{
	private_gmssl_hasher_t *this;

	INIT(this,
		.public = {
			.hasher_interface = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
	);

	this->hasher = EVP_get_digestbyname("sm3");
	if (!this->hasher)
	{
		/* OpenSSL does not support the sm3 algo */
		free(this);
		return NULL;
	}
	this->ctx = EVP_MD_CTX_create();

	/* initialization */
	if (!reset(this))
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}