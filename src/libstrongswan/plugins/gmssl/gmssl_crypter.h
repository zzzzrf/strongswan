#ifndef GMSSL_CRYPTER_H_
#define GMSSL_CRYPTER_H_

typedef struct gmssl_crypter_t gmssl_crypter_t;

#include <crypto/crypters/crypter.h>

/**
 * Implementation of crypters using GmSSL.
 */
struct gmssl_crypter_t
{
    /**
	 * Implements crypter_t interface.
	 */
	crypter_t crypter;
};

/**
 * Constructor to create gmssl_crypter_t.
 *
 * @param algo			algorithm to implement
 * @param key_size		key size in bytes
 * @return				gmssl_crypter_t, NULL if not supported
 */
gmssl_crypter_t *gmssl_crypter_create(encryption_algorithm_t algo,
												  size_t key_size);
#endif