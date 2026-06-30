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
 * @defgroup qkd_types qkd_types
 * @{ @ingroup qkd
 */

#ifndef QKD_TYPES_H_
#define QKD_TYPES_H_

#include <stdbool.h>

#include <utils/chunk.h>

typedef enum qkd_usage_t qkd_usage_t;
typedef enum qkd_mode_t qkd_mode_t;
typedef struct qkd_params_t qkd_params_t;

/**
 * Whether QKD is required or preferred.
 */
enum qkd_usage_t {
	/** Require QKD, fail negotiation if not available */
	QKD_REQUIRED = 1,
	/** Try QKD if available, fall back otherwise */
	QKD_PREFERRED = 2,
};

/**
 * QKD key combination mode.
 */
enum qkd_mode_t {
	/** Ignore QKD */
	QKD_MODE_IGNORE = 0,
	/** Use PRF mode for QKD */
	QKD_MODE_PRF = 1,
	/** Use XOR mode for QKD */
	QKD_MODE_XOR = 2,
};

/**
 * QKD negotiation parameters exchanged in IKE notify payloads.
 */
struct qkd_params_t {
	/** Whether QKD is required or preferred */
	qkd_usage_t usage;
	/** PRF or XOR mode */
	qkd_mode_t mode;
	/** Platform vendor identifier */
	chunk_t vendor;
	/** Platform or protocol version */
	chunk_t version;
	/** Opaque platform-specific configuration */
	chunk_t config;
	/** Key identifier from KMS */
	chunk_t keyid;
	/** Key length in bits, 0 if not set */
	uint32_t keylen;
	/** Encrypted key envelope */
	chunk_t envelope;
	/** Status code when has_status is TRUE (0 means success) */
	uint32_t status;
	/** TRUE if Status was present in USE_QKD */
	bool has_status;
};

/**
 * Initialize QKD parameters (zero chunks).
 */
void qkd_params_init(qkd_params_t *params);

/**
 * Destroy/clobber QKD parameters, free chunk contents.
 */
void qkd_params_destroy(qkd_params_t *params);

/**
 * Clone QKD parameters (deep copy chunks).
 */
bool qkd_params_clone(qkd_params_t *dst, qkd_params_t *src);

/**
 * Encode QKD parameters as USE_QKD (ASN.1 SET, BER).
 *
 * @param params	parameters to encode
 * @return			allocated encoding, caller must free
 */
chunk_t qkd_params_encode(qkd_params_t *params);

/**
 * Decode USE_QKD ASN.1 notify data into parameters.
 *
 * @param data		BER-encoded USE_QKD SET
 * @param params	parameters to fill (re-initialized first)
 * @return			TRUE on success
 */
bool qkd_params_decode(chunk_t data, qkd_params_t *params);

#endif /** QKD_TYPES_H_ @}*/
