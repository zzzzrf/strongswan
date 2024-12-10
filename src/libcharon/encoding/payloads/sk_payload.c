#include "sk_payload.h"

#include <daemon.h>
#include <encoding/payloads/encodings.h>

typedef struct private_sk_payload_t private_sk_payload_t;

struct private_sk_payload_t
{
    sk_payload_t public;

	uint8_t next_payload;

	uint8_t reserved;

	uint16_t payload_length;

	chunk_t sk;

	payload_type_t type;
};

static encoding_rule_t encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_sk_payload_t, next_payload)},
	// /* 8 Bit reserved bits */
	{ RESERVED_BYTE,		offsetof(private_sk_payload_t, reserved)	},
	/* Length of the whole nonce payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_sk_payload_t, payload_length)	},
	/* some nonce bytes, length is defined in PAYLOAD_LENGTH */
	{ CHUNK_DATA,		offsetof(private_sk_payload_t, sk)				},
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !    RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                Asymmetric_Encrypt(Ski, pub_r)		          ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_sk_payload_t *this)
{
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, int,
	private_sk_payload_t *this, encoding_rule_t **rules)
{
	*rules = encodings;
	return countof(encodings);
}

METHOD(payload_t, get_header_length, int,
	private_sk_payload_t *this)
{
	return 4;
}

METHOD(payload_t, get_type, payload_type_t,
	private_sk_payload_t *this)
{
	return this->type;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_sk_payload_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_sk_payload_t *this, payload_type_t type)
{
	this->next_payload = type;
}

METHOD(payload_t, get_length, size_t,
	private_sk_payload_t *this)
{
	return this->payload_length;
}

METHOD(sk_payload_t, set_sk, void,
	 private_sk_payload_t *this, chunk_t sk)
{
	this->sk = chunk_clone(sk);
	this->payload_length = get_header_length(this) + sk.len;
}

METHOD(sk_payload_t, get_sk, chunk_t,
	private_sk_payload_t *this)
{
	return chunk_clone(this->sk);
}
METHOD2(payload_t, sk_payload_t, destroy, void,
	private_sk_payload_t *this)
{
	free(this->sk.ptr);
	free(this);
}

sk_payload_t *sk_payload_create(payload_type_t type)
{
	private_sk_payload_t *this;
	INIT(this,
		.public = {
			.payload_interface = {
				.verify = _verify,
				.get_encoding_rules = _get_encoding_rules,
				.get_header_length = _get_header_length,
				.get_length = _get_length,
				.get_next_type = _get_next_type,
				.set_next_type = _set_next_type,
				.get_type = _get_type,
				.destroy = _destroy,
			},
			.set_sk = _set_sk,
			.get_sk = _get_sk,
			.destroy = _destroy,
		},
		.next_payload = PLV1_NONCE,
		.payload_length = get_header_length(this),
		.type = type,
	);
	return &this->public;
}