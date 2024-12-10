#ifndef GMSSL_UTIL_H_
#define GMSSL_UTIL_H_

#include <gmssl/sm2.h>
#include <library.h>

bool sm2_public_key_fingerprint(SM2_KEY *key, cred_encoding_type_t type, chunk_t *fp);

#endif