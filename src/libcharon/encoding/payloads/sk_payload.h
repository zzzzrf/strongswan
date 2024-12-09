#ifndef SK_PAYLOAD_H_
#define SK_PAYLOAD_H_

typedef struct sk_payload_t sk_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>

struct sk_payload_t {
	payload_t payload_interface;
	void (*set_sk)(sk_payload_t *this, chunk_t sk);
	chunk_t (*get_sk)(sk_payload_t *this);
	void (*destroy)(sk_payload_t *this);
};

sk_payload_t *sk_payload_create(payload_type_t type);
#endif