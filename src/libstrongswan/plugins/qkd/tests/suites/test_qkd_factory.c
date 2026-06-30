/*
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#include <test_suite.h>

#include <qkd/qkd_factory.h>
#include "platforms/vendor_a.h"

START_SETUP(factory_setup)
{
	lib->qkd->add_service(lib->qkd, VENDOR_A_SECTION, "1.0", vendor_a_qkd_create);
}
END_SETUP

START_TEARDOWN(factory_teardown)
{
	lib->qkd->remove_service(lib->qkd, vendor_a_qkd_create);
}
END_TEARDOWN

START_TEST(test_qkd_factory_create)
{
	qkd_service_t *service;

	ck_assert(lib->qkd != NULL);

	service = lib->qkd->create(lib->qkd, VENDOR_A_SECTION, "1.0", VENDOR_A_SECTION);
	ck_assert(service != NULL);
	ck_assert_str_eq(service->get_vendor(service).ptr, VENDOR_A_SECTION);
	service->destroy(service);
}
END_TEST

START_TEST(test_qkd_factory_unknown_vendor)
{
	ck_assert(lib->qkd->create(lib->qkd, "unknown", "1.0", "unknown") == NULL);
}
END_TEST

START_TEST(test_qkd_factory_unknown_version)
{
	ck_assert(lib->qkd->create(lib->qkd, "vendor_a", "9.9", "vendor_a") == NULL);
}
END_TEST

START_TEST(test_qkd_factory_enumerator)
{
	enumerator_t *enumerator;
	char *vendor, *version;
	qkd_service_t *service;
	enumerator = lib->qkd->create_service_enumerator(lib->qkd);

	while (enumerator->enumerate(enumerator, &vendor, &version)) {
		service = lib->qkd->create(lib->qkd, vendor, version, vendor);
		ck_assert(service != NULL);
		service->destroy(service);
	}
	enumerator->destroy(enumerator);
}
END_TEST

Suite *test_qkd_factory_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("qkd_factory");

	tc = tcase_create("factory");
	tcase_add_checked_fixture(tc, factory_setup, factory_teardown);
	tcase_add_test(tc, test_qkd_factory_create);
	tcase_add_test(tc, test_qkd_factory_unknown_vendor);
	tcase_add_test(tc, test_qkd_factory_unknown_version);
	tcase_add_test(tc, test_qkd_factory_enumerator);
	suite_add_tcase(s, tc);

	return s;
}
