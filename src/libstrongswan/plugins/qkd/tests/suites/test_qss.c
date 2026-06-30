/*
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#include <test_suite.h>

#include "platforms/platform_qss.h"

static qkd_service_t *service;

START_SETUP(qss_setup)
{
	service = qss_qkd_create(lib->settings, "qss");
	ck_assert(service != NULL);
}
END_SETUP

START_TEARDOWN(qss_teardown)
{
	service->destroy(service);
	service = NULL;
}
END_TEARDOWN

START_TEST(test_qss_get_vendor)
{
	ck_assert_str_eq(service->get_vendor(service).ptr, "qss");
}
END_TEST

START_TEST(test_qss_get_version)
{
	chunk_t version;
	version = service->get_version(service);
	ck_assert_chunk_eq(version, chunk_from_str("50331648"));
}
END_TEST

START_TEST(test_qss_fetch_keyid)
{
	identification_t *id;
	id = service->fetch_keyid(service);
	ck_assert(id != NULL);
	DBG0(DBG_APP, "id %Y", id);
	id->destroy(id);
}
END_TEST

START_TEST(test_qss_export_key)
{
	identification_t *id;
	id = service->fetch_keyid(service);
	ck_assert(id != NULL);
	DBG0(DBG_APP, "KeyID %Y", id);
	chunk_t QK = service->export_key(service, id->get_encoding(id));
	ck_assert(QK.len != 0);
	DBG0(DBG_APP, "QK %B", &QK);

	chunk_clear(&QK);
	id->destroy(id);
}
END_TEST

START_TEST(test_qss_ipsec_qdk)
{
	/* initiator */													/* responder */

	/* 				QKD REQUEST 				-->						*/
																	/* 响应方创建 QKD 服务 */
																	qkd_service_t *service_r = qss_qkd_create(lib->settings, "qss");
																	ck_assert(service_r != NULL);

																	/* 响应方申请 KEY ID */
																	identification_t *keyid_r;
																	keyid_r = service_r->fetch_keyid(service_r);
																	ck_assert(keyid_r != NULL);
																	DBG0(DBG_APP, "keyid_r %Y", keyid_r);

																	/* 响应方通过 KEY ID 获取 QK */
																	chunk_t QK_r;
																	QK_r = service_r->export_key(service_r,
																					keyid_r->get_encoding(keyid_r));
																	ck_assert(QK_r.len != 0);
																	DBG0(DBG_APP, "QK_r %B", &QK_r);
	/* 											<--					QKD RESPONSE	*/
	
	/* 发起方创建 QKD 服务 */
	qkd_service_t *service_i = qss_qkd_create(lib->settings, "qss");
	ck_assert(service_i != NULL);

	/* 发起方通过QKD RESPONSE获取 KEY ID */
	identification_t *keyid_i = keyid_r->clone(keyid_r);
	DBG0(DBG_APP, "keyid_i %Y", keyid_i);

	/* 发起方通过 KEY ID 获取 QK */
	chunk_t QK_i;
	QK_i = service_i->export_key(service_i,
			keyid_i->get_encoding(keyid_i));
	ck_assert(QK_i.len != 0);
	DBG0(DBG_APP, "QK_i %B", &QK_i);
	/* 		QKD status							-->									*/

									/* 双方的 QK 必须相等 */
									ck_assert_chunk_eq(QK_i, QK_r);
	
	keyid_r->destroy(keyid_r);
	keyid_i->destroy(keyid_i);
	chunk_clear(&QK_i);
	chunk_clear(&QK_r);
	service_r->destroy(service_r);
	service_i->destroy(service_i);
}
END_TEST

Suite *test_qss_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("qss");
	tc = tcase_create("basic");
	tcase_set_timeout(tc, 30); 
	tcase_add_checked_fixture(tc, qss_setup, qss_teardown);
	tcase_add_test(tc, test_qss_get_vendor);
	tcase_add_test(tc, test_qss_get_version);
	tcase_add_test(tc, test_qss_fetch_keyid);
	tcase_add_test(tc, test_qss_export_key);
	suite_add_tcase(s, tc);

	tc = tcase_create("IPsec QDK");
	tcase_set_timeout(tc, 30); 
	tcase_add_checked_fixture(tc, qss_setup, qss_teardown);
	tcase_add_test(tc, test_qss_ipsec_qdk);
	suite_add_tcase(s, tc);
	return s;
}
