/*
 * Copyright (C) 2015 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup unknown_payload unknown_payload
 * @{ @ingroup payloads
 */

#ifndef ID_SM_PAYLOAD_H_
#define ID_SM_PAYLOAD_H_

typedef struct id_sm_payload_t id_sm_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>

struct id_sm_payload_t {
	payload_t payload_interface;
	payload_type_t (*get_type) (id_sm_payload_t *this);
	chunk_t (*get_data) (id_sm_payload_t *this);
	void (*destroy) (id_sm_payload_t *this);
};

id_sm_payload_t *id_sm_payload_create_data(payload_type_t type, chunk_t data);

#endif
