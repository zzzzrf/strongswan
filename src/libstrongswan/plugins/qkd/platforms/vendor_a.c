/*
 * Copyright (C) 2025
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

#include "vendor_a.h"

#include <library.h>
#include <utils/debug.h>

typedef struct private_vendor_a_qkd_t private_vendor_a_qkd_t;

struct private_vendor_a_qkd_t {

	qkd_service_t public;

	chunk_t vendor;
	
	chunk_t version;

	chunk_t config;
};

METHOD(qkd_service_t, destroy, void,
	private_vendor_a_qkd_t *this)
{
	chunk_free(&this->config);
	free(this);
}

METHOD(qkd_service_t, get_vendor, chunk_t,
	private_vendor_a_qkd_t *this)
{
	return this->vendor;
}

METHOD(qkd_service_t, get_version, chunk_t,
	private_vendor_a_qkd_t *this)
{
	return this->version;
}

METHOD(qkd_service_t, fetch_keyid, identification_t *,
	private_vendor_a_qkd_t *this)
{
	return identification_create_from_string(VENDOR_A_SECTION"_KEYID_XXXXXX");
}

METHOD(qkd_service_t, export_key, chunk_t,
	private_vendor_a_qkd_t *this, chunk_t key_id)
{
	return chunk_from_hex(chunk_from_str("0x98c61dd0f8c7daf07759617546f7b3ae156f19a7bc935c61523c7ca998e5eedb"), NULL);
}

METHOD(qkd_service_t, process_request, status_t,
	private_vendor_a_qkd_t *this, qkd_params_t *req, qkd_params_t *resp)
{
	identification_t *key_id;
	if (!chunk_equals(req->vendor, this->vendor) ||
				!chunk_equals(req->version, this->version))
	{
		return FAILED;
	}

	qkd_params_clone(resp, req);
	key_id = fetch_keyid(this);
	resp->keyid = chunk_clone(key_id->get_encoding(key_id));
	resp->keylen = resp->keyid.len;
	resp->has_status = TRUE;
	resp->status = SUCCESS;

	DBG1(DBG_LIB, "%s QKD KEY ID : %b, status : %d", VENDOR_A_SECTION,
								resp->keyid.ptr, resp->keyid.len, resp->status);
	return SUCCESS;
}

METHOD(qkd_service_t, process_response, status_t,
	private_vendor_a_qkd_t *this, qkd_params_t *resp, qkd_params_t *out)
{
	// uint32_t key_len = 0;
	identification_t *key_id;
	if (!chunk_equals(resp->vendor, this->vendor) ||
				!chunk_equals(resp->version, this->version))
	{
		return FAILED;
	}

	qkd_params_init(out);
	key_id = identification_create_from_data(resp->keyid);
	// key_len = resp->keylen;

	out->has_status = TRUE;
	out->status = SUCCESS;

	DBG1(DBG_LIB, "%s QKD RECV KEY ID : %Y, status : %d", VENDOR_A_SECTION,
		key_id, resp->status);
	key_id->destroy(key_id);
	return SUCCESS;
}

qkd_service_t *vendor_a_qkd_create(settings_t *settings, char *section)
{
	private_vendor_a_qkd_t *this;
	char *config_str = NULL;

	// int mode = settings->get_int(settings, "%s.plugins.qkd.%s.mode", 1, lib->ns, section);
	// DBG3(DBG_CFG, "vendor_a_qkd_create mode : %d\n", mode);
	config_str = settings->get_str(settings, "%s.plugins.qkd.%s.config",
							"default_config", lib->ns, section);

	DBG3(DBG_CFG, "vendor_a_qkd_create config : %s\n", config_str);

	INIT(this,
		.public = {
			.destroy = _destroy,
			.get_vendor = _get_vendor,
			.get_version = _get_version,
			.fetch_keyid = _fetch_keyid,
			.export_key = _export_key,
			.process_request = _process_request,
			.process_response = _process_response,
		},
		.vendor = chunk_from_str(VENDOR_A_SECTION),
		.version = chunk_from_str("1.0"),
		.config = chunk_clone(chunk_from_str(config_str)),
	);

	return &this->public;
}
