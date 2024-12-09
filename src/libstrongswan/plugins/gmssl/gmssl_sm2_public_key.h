#ifndef GMSSL_SM2_PUBLIC_KEY_H_
#define GMSSL_SM2_PUBLIC_KEY_H_

#include <credentials/builder.h>
#include <credentials/cred_encoding.h>
#include <credentials/keys/public_key.h>

typedef struct sm2_public_key_t sm2_public_key_t;

struct sm2_public_key_t {
    public_key_t key;
};

sm2_public_key_t *sm2_public_key_load(key_type_t type, va_list args);
#endif