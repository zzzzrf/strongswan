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

#include "qkd_plugin.h"

#include <library.h>
#include <utils/debug.h>

#include "platforms/vendor_a.h"
#include "platforms/platform_qss.h"

typedef struct private_qkd_plugin_t private_qkd_plugin_t;

struct private_qkd_plugin_t {

	qkd_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_qkd_plugin_t *this)
{
	return "qkd";
}

METHOD(plugin_t, get_features, int,
	private_qkd_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		// PLUGIN_REGISTER(QKD, vendor_a_qkd_create),
		// 	PLUGIN_PROVIDE(QKD, "vendor_a", "1.0"),
		PLUGIN_REGISTER(QKD, qss_qkd_create),
			PLUGIN_PROVIDE(QKD, "qss", "50331648"),
				PLUGIN_SDEPEND(RNG, RNG_STRONG),
		/* add further platforms here, e.g.:
		PLUGIN_REGISTER(QKD, vendor_b_qkd_create),
			PLUGIN_PROVIDE(QKD, "vendor_b", "1.0"),
				PLUGIN_SDEPEND(FETCHER, "http://"),
		*/
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_qkd_plugin_t *this)
{
	free(this);
}

PLUGIN_DEFINE(qkd)
{
	private_qkd_plugin_t *this;

	if (!lib->qkd)
	{
		DBG1(DBG_LIB, "qkd plugin requires QKD support (enable-qkd)");
		return NULL;
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
