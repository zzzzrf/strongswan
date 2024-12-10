#ifndef GMSSL_HMAC_H_
#define GMSSL_HMAC_H_

#include <crypto/prfs/prf.h>
#include <crypto/signers/signer.h>


/**
 * Creates a new prf_t object based on an HMAC.
 *
 * @param algo		algorithm to implement
 * @return			prf_t object, NULL if not supported
 */
prf_t *gmssl_hmac_prf_create(pseudo_random_function_t algo);

/**
 * Creates a new signer_t object based on an HMAC.
 *
 * @param algo		algorithm to implement
 * @return			signer_t, NULL if not supported
 */
signer_t *gmssl_hmac_signer_create(integrity_algorithm_t algo);


#endif