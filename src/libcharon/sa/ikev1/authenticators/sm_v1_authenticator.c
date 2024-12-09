#include "sm_v1_authenticator.h"

#include <daemon.h>
#include <sa/ikev1/keymat_v1.h>
#include <encoding/payloads/hash_payload.h>

typedef struct private_sm_v1_authenticator_t private_sm_v1_authenticator_t;

struct private_sm_v1_authenticator_t {
    sm_v1_authenticator_t public;
	ike_sa_t *ike_sa;
	bool initiator;
	chunk_t sa_payload;
	chunk_t id_payload;
};

METHOD(authenticator_t, build, status_t,
	private_sm_v1_authenticator_t *this, message_t *message)
{
	hash_payload_t *hash_payload;
	keymat_v1_t *keymat;
	chunk_t hash;

	keymat = (keymat_v1_t*)this->ike_sa->get_keymat(this->ike_sa);
	if (!keymat->get_sm_hash(keymat, this->initiator,
							this->ike_sa->get_id(this->ike_sa),
							this->sa_payload, this->id_payload,
							&hash))
	{
		return FAILED;
	}

	hash_payload = hash_payload_create(PLV1_HASH);
	hash_payload->set_hash(hash_payload, hash);
	message->add_payload(message, &hash_payload->payload_interface);
	free(hash.ptr);
	return SUCCESS;
}

METHOD(authenticator_t, process, status_t,
	private_sm_v1_authenticator_t *this, message_t *message)
{
	hash_payload_t *hash_payload;
	keymat_v1_t *keymat;
	auth_cfg_t *auth;
	chunk_t hash;

	hash_payload = (hash_payload_t*)message->get_payload(message, PLV1_HASH);
	if (!hash_payload)
	{
		DBG1(DBG_IKE, "HASH payload missing in message");
		return FAILED;
	}

	keymat = (keymat_v1_t*)this->ike_sa->get_keymat(this->ike_sa);
	if (!keymat->get_sm_hash(keymat, !this->initiator,
					this->ike_sa->get_id(this->ike_sa), this->sa_payload,
					this->id_payload, &hash))
	{
		return FAILED;
	}

	if (chunk_equals_const(hash, hash_payload->get_hash(hash_payload)))
	{
		auth = this->ike_sa->get_auth_cfg(this->ike_sa, FALSE);
		auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
		free(hash.ptr);
		return SUCCESS;
	}
	free(hash.ptr);
	DBG1(DBG_IKE, "calculated HASH does not match HASH payload");
	return FAILED;
}

METHOD(authenticator_t, destroy, void,
	private_sm_v1_authenticator_t *this)
{
	chunk_free(&this->id_payload);
	free(this);
}

sm_v1_authenticator_t *sm_v1_authenticator_create(ike_sa_t *ike_sa,
										bool initiator, chunk_t sa_payload, chunk_t id_payload)
{
    private_sm_v1_authenticator_t *this;

	INIT(this,
		.public = {
			.authenticator = {
				.build = _build,
				.process = _process,
				.is_mutual = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.initiator = initiator,
		.sa_payload = sa_payload,
		.id_payload = id_payload,
	);

	return &this->public;
}
