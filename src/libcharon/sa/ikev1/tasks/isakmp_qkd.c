#include "isakmp_qkd.h"

typedef struct private_isakmp_qkd_t private_isakmp_qkd_t;

struct private_isakmp_qkd_t {
	isakmp_qkd_t public;

	ike_sa_t *ike_sa;
	enum {
		QKD_REQ,
		QKD_DONE,
		QKD_IGNORE,
	} state;
	qkd_service_t *qkd_service;
	qkd_params_t QKD_r;
	qkd_params_t QKD_s;
};

METHOD(task_t, get_type, task_type_t,
	private_isakmp_qkd_t *this)
{
	return TASK_ISAKMP_QKD;
}

METHOD(task_t, migrate, void,
	private_isakmp_qkd_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
	this->state = QKD_REQ;
	qkd_params_destroy(&this->QKD_s);
	qkd_params_destroy(&this->QKD_r);
	DESTROY_IF(this->qkd_service);
	this->qkd_service = NULL;
}

METHOD(task_t, destroy, void,
	private_isakmp_qkd_t *this)
{
	qkd_params_destroy(&this->QKD_s);
	qkd_params_destroy(&this->QKD_r);
	DESTROY_IF(this->qkd_service);
	this->qkd_service = NULL;
	free(this);
}

METHOD(task_t, build_i, status_t,
	private_isakmp_qkd_t *this, message_t *message)
{
	notify_payload_t *notify;
	peer_cfg_t *peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
	enumerator_t *enumerator = NULL;

	switch (this->state)
	{
		case QKD_REQ:
		{
			char *vendor, *version;
			if (peer_cfg->get_qkd_mode(peer_cfg) == QKD_MODE_IGNORE)
			{
				this->state = QKD_IGNORE;
				return SUCCESS;
			}

			enumerator = lib->qkd->create_service_enumerator(lib->qkd);
			while (enumerator->enumerate(enumerator, &vendor, &version))
			{
				qkd_params_t qkd_params;
				chunk_t encoded;

				qkd_params_init(&qkd_params);
				qkd_params.usage = peer_cfg->has_option(peer_cfg, OPT_QKD_REQUIRED) ?
												QKD_REQUIRED : QKD_PREFERRED;
				qkd_params.mode = peer_cfg->get_qkd_mode(peer_cfg);
				qkd_params.vendor = chunk_clone(chunk_from_str(vendor));
				qkd_params.version = chunk_clone(chunk_from_str(version));

				notify = notify_payload_create_from_protocol_and_type(PLV1_NOTIFY,
					PROTO_IKE, QKD_REQUEST);

				encoded = qkd_params_encode(&qkd_params);
				notify->set_notification_data(notify, encoded);

				message->add_payload(message, &notify->payload_interface);
				DBG0(DBG_IKE, "Add USE_QKDi(%s|%s|%s|%s) Payload",
									qkd_params.usage == QKD_REQUIRED ? "QKD_REQUIRED" : "QKD_PREFERRED",
									qkd_params.mode == QKD_MODE_PRF ? "QKD_MODE_PRF" : "QKD_MODE_XOR",
									vendor, version);
				chunk_free(&encoded);
				qkd_params_destroy(&qkd_params);
			}
			enumerator->destroy(enumerator);
			return NEED_MORE;
		}
		case QKD_DONE:
		{
			notify = notify_payload_create_from_protocol_and_type(PLV1_NOTIFY,
									PROTO_IKE, QKD_REQUEST);
			DBG0(DBG_IKE, "ADD USE_QKDs Payload");
			chunk_t encoded;
			encoded = qkd_params_encode(&this->QKD_s);
			notify->set_notification_data(notify, encoded);
			message->add_payload(message, &notify->payload_interface);

			chunk_free(&encoded);
			return SUCCESS;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, process_i, status_t,
	private_isakmp_qkd_t *this, message_t *message)
{
	chunk_t QKD_KEY = chunk_empty;
	qkd_service_t *service = NULL;
	peer_cfg_t *peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
	switch (this->state)
	{
		case QKD_REQ:
		{
			qkd_params_t decoded;
			chunk_t vendor, version;
			DBG0(DBG_IKE, "Parse USE_QKDr Payload");
			notify_payload_t *notify = message->get_notify(message, QKD_REQUEST);
			if (notify == NULL)
			{
				if (peer_cfg->has_option(peer_cfg, OPT_QKD_REQUIRED))
				{
					DBG1(DBG_IKE, "no QKD_REQUEST notify in response, QKD negotiation failed");
					return FAILED;
				}
				return SUCCESS;
			}

			chunk_t encoded = notify->get_notification_data(notify);
			qkd_params_decode(encoded, &decoded);
			if (!decoded.has_status || (decoded.has_status && decoded.status != 0))
			{
				qkd_params_destroy(&decoded);
				return FAILED;
			}

			version = chunk_empty;
			if (!decoded.vendor.len)
			{
				DBG0(DBG_IKE, "USE_QKDi missing vendor");
				qkd_params_destroy(&decoded);
				return FAILED;
			}
			vendor = chunk_cat("cc", decoded.vendor, chunk_from_chars(0x00));
			if (decoded.version.len)
			{
				version = chunk_cat("cc", decoded.version,
									chunk_from_chars(0x00));
			}
			service = lib->qkd->create(lib->qkd, (char*)vendor.ptr,
						version.len ? (char*)version.ptr : NULL,
						(char*)vendor.ptr);
			if (service == NULL)
			{
				DBG1(DBG_IKE, "create QKD Service (%s %s) failed", vendor.ptr,
								version.len ? (char*)version.ptr : "");
				chunk_free(&vendor);
				chunk_free(&version);
				qkd_params_destroy(&decoded);
				return FAILED;
			}

			if (service->process_response(service, &decoded, &this->QKD_s) == SUCCESS)
			{
				QKD_KEY = service->export_key(service, decoded.keyid);
				this->ike_sa->clone_qkd_key(this->ike_sa, QKD_KEY);
			}

			DESTROY_IF(this->qkd_service);
			this->qkd_service = service;

			chunk_free(&vendor);
			chunk_free(&version);
			qkd_params_destroy(&decoded);
			this->state = QKD_DONE;
			return NEED_MORE;
		}
		case QKD_IGNORE:
		{
			return NEED_MORE;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, build_r, status_t,
	private_isakmp_qkd_t *this, message_t *message)
{
	if (this->qkd_service == NULL)
	{
		DBG0(DBG_IKE, "no QKD Service");
		return FAILED;
	}

	switch (this->state)
	{
		case QKD_REQ:
		{
			chunk_t encoded;
			notify_payload_t *notify = notify_payload_create_from_protocol_and_type(PLV1_NOTIFY,
								PROTO_IKE, QKD_REQUEST);

			encoded = qkd_params_encode(&this->QKD_r);
			notify->set_notification_data(notify, encoded);
			message->add_payload(message, &notify->payload_interface);
			DBG0(DBG_IKE, "Add USE_QKDr Payload");
			this->state = QKD_DONE;

			chunk_free(&encoded);

			return NEED_MORE;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, process_r, status_t,
	private_isakmp_qkd_t *this, message_t *message)
{
	notify_payload_t *notify = NULL;
	qkd_service_t * service = NULL;
	chunk_t QKD_KEY = chunk_empty;

	notify = message->get_notify(message, QKD_REQUEST);

	if (notify == NULL)
		return SUCCESS;

	switch (this->state)
	{
		case QKD_REQ:
		{
			chunk_t vendor, version;
			chunk_t encoded = notify->get_notification_data(notify);
			qkd_params_t qkd_params;
			if (qkd_params_decode(encoded, &qkd_params) == FALSE)
			{
				DBG0(DBG_IKE, "USE_QKDi decode failed");
				return FAILED;
			}

			version = chunk_empty;
			if (!qkd_params.vendor.len)
			{
				DBG0(DBG_IKE, "USE_QKDi missing vendor");
				qkd_params_destroy(&qkd_params);
				return FAILED;
			}
			vendor = chunk_cat("cc", qkd_params.vendor, chunk_from_chars(0x00));
			if (qkd_params.version.len)
			{
				version = chunk_cat("cc", qkd_params.version,
									chunk_from_chars(0x00));
			}
			service = lib->qkd->create(lib->qkd, (char*)vendor.ptr,
						version.len ? (char*)version.ptr : NULL,
						(char*)vendor.ptr);
			if (service)
			{
				DBG0(DBG_IKE, "receive USE_QKDi(%s|%s|%s|%s)",
					qkd_params.usage == QKD_REQUIRED ? "QKD_REQUIRED" : "QKD_PREFERRED",
					qkd_params.mode == QKD_MODE_PRF ? "QKD_MODE_PRF" : "QKD_MODE_XOR",
					vendor.ptr, version.ptr);
				if (service->process_request(service, &qkd_params, &this->QKD_r) == SUCCESS )
				{
					QKD_KEY = service->export_key(service, this->QKD_r.keyid);
					this->ike_sa->clone_qkd_key(this->ike_sa, QKD_KEY);
				}
				else
				{
					service->destroy(service);
					service = NULL;
				}
			}
			else
			{
				DBG0(DBG_IKE, "create qkd service failed");
			}

			this->qkd_service = service;
			chunk_free(&vendor);
			chunk_free(&version);
			qkd_params_destroy(&qkd_params);
			return NEED_MORE;
		}
		case QKD_DONE:
		{
			DBG0(DBG_IKE, "receive USE_QKDs");
			chunk_t buffer = notify->get_notification_data(notify);
			DBG4(DBG_IKE, "receive USE_QKDs : %B", &buffer);
			return SUCCESS;
		}
		default:
			return FAILED;
	}
}

isakmp_qkd_t *isakmp_qkd_create(ike_sa_t *ike_sa, bool initiator)
{
	private_isakmp_qkd_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.state = QKD_REQ,
	);

	if (initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}

	return &this->public;
}