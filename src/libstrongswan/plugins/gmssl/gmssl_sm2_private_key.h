#ifndef GMSSL_SM2_PRIVATE_KEY_H_
#define GMSSL_SM2_PRIVATE_KEY_H_

#include <credentials/builder.h>
#include <credentials/keys/private_key.h>

typedef struct sm2_private_key_t sm2_private_key_t;

struct sm2_private_key_t 
{
    private_key_t key;
};

sm2_private_key_t *sm2_private_key_gen(key_type_t type, va_list args);
sm2_private_key_t *sm2_private_key_load(key_type_t type, va_list args);
#endif