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
 * @defgroup qkd_factory qkd_factory
 * @{ @ingroup qkd
 */

#ifndef QKD_FACTORY_H_
#define QKD_FACTORY_H_

typedef struct qkd_factory_t qkd_factory_t;

#include <qkd/qkd_service.h>

/**
 * Constructor for a QKD platform service.
 *
 * @param settings		library settings
 * @param section		settings subsection name (under qkd.*)
 * @return				service instance, NULL if failed
 */
typedef qkd_service_t* (*qkd_service_constructor_t)(settings_t *settings,
													char *section);

/**
 * Registry and factory for QKD platform services.
 */
struct qkd_factory_t {

	/**
	 * Create a QKD service for the given vendor and version.
	 *
	 * @param vendor		vendor name
	 * @param version		platform version, NULL for default lookup
	 * @param section		settings subsection (e.g. same as vendor)
	 * @return				service, NULL if vendor unknown or failed
	 */
	qkd_service_t* (*create)(qkd_factory_t *this, char *vendor, char *version,
							 char *section);

	/**
	 * Register a QKD platform constructor.
	 *
	 * @param vendor		vendor name
	 * @param version		platform version, NULL if unspecified
	 * @param create		constructor function
	 */
	void (*add_service)(qkd_factory_t *this, char *vendor, char *version,
						qkd_service_constructor_t create);

	/**
	 * Unregister a previously registered constructor.
	 *
	 * @param create		constructor to remove
	 */
	void (*remove_service)(qkd_factory_t *this,
						   qkd_service_constructor_t create);

	/**
	 * Create an enumerator over registered QKD platform services.
	 *
	 * @return				enumerator (char *vendor, char *version)
	 */
	enumerator_t* (*create_service_enumerator)(qkd_factory_t *this);

	/**
	 * Destroy the factory.
	 */
	void (*destroy)(qkd_factory_t *this);
};

/**
 * Create a QKD factory instance.
 */
qkd_factory_t *qkd_factory_create();

#endif /** QKD_FACTORY_H_ @}*/
