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

#include "platform_qss.h"
#include "qss_sdk.h"
#include <library.h>
#include <utils/debug.h>
#include <crypto/rngs/rng.h>
 
typedef struct private_vendor_a_qkd_t private_vendor_a_qkd_t;
 
struct private_vendor_a_qkd_t {
 
	qkd_service_t public;

	chunk_t vendor;
	
	chunk_t version;

	chunk_t config;

	MiniDevInfo_st dev_info[8];

	void *app;

	char *config_file_path;

	STCALLBACK stc_cb;
};

void platform_qss_watch_cb(int srv_state, void* hDevHandle)
{
	DBG2(DBG_LIB, "platform_qss_watch_cb srv state : %x", srv_state);
	switch (srv_state)
	{
		case 1:
			break;
		case 2:
			break;
		case 3:
			break;
		case 4:
			break;
		default:
			return ;
	}
}

METHOD(qkd_service_t, destroy, void,
	private_vendor_a_qkd_t *this)
{
	chunk_free(&this->version);
	chunk_free(&this->config);
	QSS_Logout(this->app, this->dev_info[0].hDevHandle);
	QSS_Finalize(this->app);
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
	char bussiness_id[32] = {'1', '2', '3', '4', '5', '6', '7', '8', '\0'};
	unsigned char key_id[128];
	unsigned int key_id_len = sizeof(key_id);
	void *crypto_dev;
	int ret;
	identification_t *identification = NULL;

	ret = QSS_ApplyGroupSessionQKey(this->app, this->dev_info[0].hDevHandle, bussiness_id,
		key_id, &key_id_len, &crypto_dev, SGD_SMS4_ECB, 16, 365);
	if (ret == SAR_OK || ret == SAR_NeedChargeButReqKeySucc)
	{
		DBG2(DBG_LIB, "QSS_ApplyGroupSessionQKey SUCCESS");
		identification = identification_create_from_string(key_id);
	}
	else
	{
		DBG0(DBG_LIB, "QSS_ApplyGroupSessionQKey FAIL, errcode::%x", ret);
	}

	QSS_CloseSessionQKeyHandle(this->app, this->dev_info[0].hDevHandle, crypto_dev);

	return identification;
}

METHOD(qkd_service_t, export_key, chunk_t,
	private_vendor_a_qkd_t *this, chunk_t key_id)
{
	int ret;
	unsigned char key_id_str[128] = {0};
	unsigned char pOutSessionKey[256];
	unsigned int SessionKekLen = sizeof(pOutSessionKey);

	memcpy(key_id_str, key_id.ptr, key_id.len);
	ret = QSS_ExportSessionQKey(this->app, this->dev_info[0].hDevHandle, 
						key_id_str, pOutSessionKey, &SessionKekLen);

	if (ret != SAR_OK)
	{
		DBG2(DBG_LIB, "QSS_ExportSessionQKey FAIL errcode::%x, key_id : %B", ret, &key_id);
		return chunk_empty;
	}

	return chunk_clone(chunk_create(pOutSessionKey, SessionKekLen));
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

	DBG1(DBG_LIB, "%s QKD KEY ID : %b, status : %d", PLATFORM_QSS_SECTION,
								resp->keyid.ptr, resp->keyid.len, resp->status);
	key_id->destroy(key_id);

	return SUCCESS;
}

METHOD(qkd_service_t, process_response, status_t,
	private_vendor_a_qkd_t *this, qkd_params_t *resp, qkd_params_t *out)
{
	int ret;
	void *crypto_dev;
	unsigned char key_id_str[128] = {0};
	char bussiness_id[32] = {'1', '2', '3', '4', '5', '6', '7', '8', '\0'};

	if (!chunk_equals(resp->vendor, this->vendor) ||
				!chunk_equals(resp->version, this->version))
	{
		return FAILED;
	}

	qkd_params_init(out);
	out->has_status = TRUE;
	memcpy(key_id_str, resp->keyid.ptr, resp->keyid.len);
	ret = QSS_GetSessionQKey(this->app, this->dev_info[0].hDevHandle, 
		bussiness_id, key_id_str, SGD_SMS4_ECB, &crypto_dev);
	if (ret == SAR_OK || ret == SAR_NeedChargeButReqKeySucc)
	{
		DBG2(DBG_LIB, "Download QK Success");
		out->status = SUCCESS;
	}
	else
	{
		DBG2(DBG_LIB, "Download QK Fail : errcode::%x, KEY ID : %b", ret, resp->keyid.ptr, resp->keyid.len);
		out->status = FAILED;
	}
	QSS_CloseSessionQKeyHandle(this->app, this->dev_info[0].hDevHandle, crypto_dev);

	DBG1(DBG_LIB, "%s QKD RECV KEY ID : %b, status : %d", PLATFORM_QSS_SECTION,
		resp->keyid.ptr, resp->keyid.len, resp->status);

	return SUCCESS;
}
 
qkd_service_t *qss_qkd_create(settings_t *settings, char *section)
{
	private_vendor_a_qkd_t *this;

	char client_id[32];
	uint32_t client_num = 1;
	rng_t *rng;
	int ret;
	uint32_t status = 0;
	unsigned int qss_version;
	char *ver_str = NULL;
	const char app_signature[] = "";

	ret = QSS_GetVersion(&qss_version);
	if (ret != SAR_OK)
	{
		DBG0(DBG_LIB, "QSS_GetVersion ret : %d", ret);
		return NULL;
	}
	if (asprintf(&ver_str, "%u", qss_version) < 0)
	{
		return NULL;
	}

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
		.stc_cb = platform_qss_watch_cb,
		.vendor = chunk_from_str(PLATFORM_QSS_SECTION),
		.version = chunk_create((u_char*)ver_str, strlen(ver_str)),
		.config_file_path = settings->get_str(settings, "%s.plugins.qkd.%s.config_file_path",
			"/home/zrf/git/ipsec/src/libstrongswan/plugins/qkd/platforms/x86test/xt_config.json", lib->ns, section),
	);

	ret = QSS_Initialize(&this->app, this->config_file_path, app_signature);
	if (ret != SAR_OK)
	{
		DBG0(DBG_LIB, "QSS_Initialize ret : %x, sfilename : %s", ret, this->config_file_path);
		free(ver_str);
		free(this);
		return NULL;
	}

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (rng)
	{
		if (rng->get_bytes(rng, sizeof(client_num), (uint8_t*)&client_num))
		{
			client_num = (client_num % 999999) + 1;
		}
		rng->destroy(rng);
	}
	snprintf(client_id, sizeof(client_id), "ZSVPN%u", client_num);

	ret = QSS_StartSoftCard(this->app, client_id, 
			NULL, "12345678", &this->dev_info[0].hDevHandle);
	if (ret != SAR_OK)
	{
		DBG0(DBG_LIB, "QSS_StartSoftCard ret : %x, client_id : %s", ret, client_id);
		free(ver_str);
		QSS_Finalize(this->app);
		free(this);
		return NULL;
	}

	ret = QSS_CheckDeviceStatus(this->app, this->dev_info[0].hDevHandle, &this->dev_info[0], &status, 0);
	if (ret != SAR_OK)
	{
		DBG0(DBG_LIB, "QSS_CheckDeviceStatus ret : %d", ret);
		destroy(this);
		return NULL;
	}

	if (status == 3)
	{
		ret = QSS_DeviceNetIn(this->app, this->dev_info[0].hDevHandle, client_id, "miao-test", NULL);
		if (ret != SAR_OK)
		{
			DBG0(DBG_LIB, "QSS_DeviceNetIn ret : %d", ret);
			destroy(this);
			return NULL;
		}
	}

	uint32_t retry = 0;
	ret = QSS_VerifyPin(this->app, this->dev_info[0].hDevHandle, "12345678", &retry, 0);
	if (ret != SAR_OK)
	{
		DBG0(DBG_LIB, "QSS_VerifyPin ret : %d, retry : %d", ret, retry);
		destroy(this);
		return NULL;
	}

	ret = QSS_RegSrvStatusMonitor(this->stc_cb, this);
	if (ret != SAR_OK)
	{
		DBG0(DBG_LIB, "QSS_RegSrvStatusMonitor ret : %d", ret);
		destroy(this);
		return NULL;
	}

	return &this->public;
}
 