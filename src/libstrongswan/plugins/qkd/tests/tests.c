/*
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#include <test_runner.h>

/* declare test suite constructors */
#define TEST_SUITE(x) test_suite_t* x();
#define TEST_SUITE_DEPEND(x, ...) TEST_SUITE(x)
#include "tests.h"
#undef TEST_SUITE
#undef TEST_SUITE_DEPEND

static test_configuration_t tests[] = {
#define TEST_SUITE(x) \
	{ .suite = x, },
#define TEST_SUITE_DEPEND(x, type, ...) \
	{ .suite = x, .feature = PLUGIN_DEPENDS(type, __VA_ARGS__) },
#include "tests.h"
	{ .suite = NULL, }
};

static bool test_runner_init(bool init)
{
	if (init)
	{
		char *plugins, *plugindir;
		plugins = getenv("TESTS_PLUGINS") ?:
					lib->settings->get_str(lib->settings,
										"tests.load", "random");
		plugindir = lib->settings->get_str(lib->settings,
										"tests.plugindir", "/etc/strongswan.d/charon");
		plugin_loader_add_plugindirs(plugindir, plugins);
		if (!lib->plugins->load(lib->plugins, plugins))
		{
			return FALSE;
		}
		lib->plugins->status(lib->plugins, LEVEL_CTRL);
		lib->processor->set_threads(lib->processor, 0);
		lib->processor->cancel(lib->processor);
	}
	return TRUE;
}

int main(int argc, char *argv[])
{
	return test_runner_run("qkd", tests, test_runner_init);
}
