/*
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#include <test_suite.h>

#include "platforms/vendor_a.h"

static qkd_service_t *service;

START_SETUP(vendor_a_setup)
{
	service = vendor_a_qkd_create(lib->settings, "vendor_a");
	ck_assert(service != NULL);
}
END_SETUP

START_TEARDOWN(vendor_a_teardown)
{
	service->destroy(service);
	service = NULL;
}
END_TEARDOWN

START_TEST(test_vendor_a_get_vendor)
{
	ck_assert_str_eq(service->get_vendor(service).ptr, "vendor_a");
}
END_TEST

Suite *test_vendor_a_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("vendor_a");

	tc = tcase_create("service");
	tcase_add_checked_fixture(tc, vendor_a_setup, vendor_a_teardown);
	tcase_add_test(tc, test_vendor_a_get_vendor);
	suite_add_tcase(s, tc);

	return s;
}
