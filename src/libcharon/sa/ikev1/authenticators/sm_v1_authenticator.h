#ifndef SM_V1_AUTHENTICATOR_H_
#define SM_V1_AUTHENTICATOR_H_

typedef struct sm_v1_authenticator_t sm_v1_authenticator_t;

#include <sa/authenticator.h>

struct sm_v1_authenticator_t {
	authenticator_t authenticator;
};

sm_v1_authenticator_t *sm_v1_authenticator_create(ike_sa_t *ike_sa,
										bool initiator, chunk_t sa_payload, chunk_t id_payload);

#endif
