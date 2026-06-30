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

/**
 * @defgroup qkd_service qkd_service
 * @{ @ingroup qkd
 */

#ifndef QKD_SERVICE_H_
#define QKD_SERVICE_H_

typedef struct qkd_service_t qkd_service_t;

#include <qkd/qkd_types.h>
#include <settings/settings.h>
#include <utils/identification.h>

/**
 * QKD platform service instance.
 */
struct qkd_service_t {
	/**
	 * Destroy a QKD service instance.
	 */
	void (*destroy)(qkd_service_t *this);

	/**
	 * Get the vendor name for this service.
	 *
	 * @return			vendor string, internal data
	 */
	chunk_t (*get_vendor)(qkd_service_t *this);

	/**
	 * Get the version for this service.
	 *
	 * @return			version string, internal data
	 */
	chunk_t (*get_version)(qkd_service_t *this);

	/**
	 * Get the config for this service.
	 *
	 * @return			config string, internal data
	 */
	chunk_t (*get_config)(qkd_service_t *this);

	/**
	* Fetch key identifier for this service.
	*
	* @return			key identifier object
	 */
	identification_t *(*fetch_keyid)(qkd_service_t *this);

	/**
	* Export key for this service.
	 *
	 * @param keyid		key identifier
	 * @return			key, internal data
	 */
	chunk_t (*export_key)(qkd_service_t *this, chunk_t keyid);

	/**
	 * Process an incoming QKD request (responder side).
	 *
	 * @param req		request parameters from peer
	 * @param resp		response parameters to fill
	 * @return			SUCCESS, FAILED, etc.
	 */
	status_t (*process_request)(qkd_service_t *this,
							  qkd_params_t *req, qkd_params_t *resp);
	
	/**
	 * Process a QKD response (initiator follow-up).
	 *
	 * @param resp		response from peer
	 * @param out		result parameters to fill
	 * @return			SUCCESS, FAILED, etc.
	 */
	status_t (*process_response)(qkd_service_t *this,
								 qkd_params_t *resp, qkd_params_t *out);
};

#endif /** QKD_SERVICE_H_ @}*/
