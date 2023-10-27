#ifndef GMSSL_HASHER_H_
#define GMSSL_HASHER_H_

typedef struct gmssl_hasher_t gmssl_hasher_t;

#include <crypto/hashers/hasher.h>


struct gmssl_hasher_t {

	/**
	 * Implements hasher_t interface.
	 */
	hasher_t hasher_interface;
};

/**
 * Constructor to create gmssl_hasher_t.
 *
 * @param algo			algorithm
 * @return				gmssl_hasher_t, NULL if not supported
 */
gmssl_hasher_t *gmssl_hasher_create(hash_algorithm_t algo);

#endif