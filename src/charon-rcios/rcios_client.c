#include "rcios_client.h"
#include "rcios_cmds.h"

#include <processing/jobs/callback_job.h>

typedef struct private_rcios_client_t private_rcios_client_t;

struct private_rcios_client_t
{
	rcios_client_t public;
	stream_t *stream;
	u_int mod_id;
};

METHOD(rcios_client_t, send_, bool,
	private_rcios_client_t *this, u_int cmd_code, chunk_t data)
{
	char buffer[RCIOS_MESSAGE_SIZE_MAX] = {0};
	rcios_rpc_hdr_t *phdr;

	if (data.len + sizeof(rcios_rpc_hdr_t) > RCIOS_MESSAGE_SIZE_MAX)
		return false;

	phdr = (rcios_rpc_hdr_t *)buffer;
	phdr->mod_id = this->mod_id;
	IOS_RPC_SET_FLAGS(phdr, IOS_RPC_REQ);
	phdr->cmd_code = cmd_code;
	phdr->datalen = data.len;
	memcpy(phdr->data, data.ptr, data.len);
	DBG1(DBG_APP, "send %d cmd, header : %b", cmd_code, phdr, sizeof(rcios_rpc_hdr_t));
	DBG1(DBG_APP, "send %d cmd, data : %B", cmd_code, &data);
	return this->stream->write_all(this->stream, phdr, sizeof(rcios_rpc_hdr_t) + data.len);
}

METHOD(rcios_client_t, destroy, void,
		private_rcios_client_t *this)
{
	DESTROY_IF(this->stream);
	free(this);
}

rcios_client_t *rcios_client_create(u_int mod_id, char *uri)
{
	private_rcios_client_t *this;

	INIT(this,
		.public = {
			.send = _send_,
			.destroy = _destroy,
		},
		.mod_id = mod_id,
	);
	this->stream = lib->streams->connect(lib->streams, uri);
	if (!this->stream)
	{
		free(this);
		return NULL;
	}
	return &this->public;
}

static job_requeue_t disconnect_async(rcios_client_entry_t *this)
{
	DESTROY_IF(this->client);
	return JOB_REQUEUE_NONE;
}

static void disconnect(rcios_client_entry_t *this)
{
	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((void*)disconnect_async, this,
										free, NULL));
}

CALLBACK(client_read, bool,
	rcios_client_entry_t *entry, stream_t *stream)
{
	rcios_rpc_hdr_t hdr;
	char buffer[RCIOS_MESSAGE_SIZE_MAX] = {0};

	while (TRUE)
	{
		stream->read_all(stream, &hdr, sizeof(rcios_rpc_hdr_t));
		stream->read_all(stream, buffer, hdr.datalen);

		if (entry->cb)
			entry->cb(entry, &hdr, chunk_create(buffer, hdr.datalen));

		if (hdr.flags & 0xf & IOS_RPC_ACK)
		{
			disconnect(entry);
			return TRUE;
		}
	}

	return TRUE;
}

#define RC_CMD_SET_GATEWAY_PAYLOAD "name : n2n"

void rcios_client_set_gateway(u_int mod_id, char *uri, rcios_client_rpc_cb cb)
{
	rcios_client_entry_t *entry;

	INIT(entry,
		.client = rcios_client_create(mod_id, uri),
		.cmd_code = IPSECD_CMD_SET_GATEWAY,
		.data = chunk_from_str(RC_CMD_SET_GATEWAY_PAYLOAD),
		.cb = cb,
	);
	entry->stream = ((private_rcios_client_t *)entry->client)->stream,

	entry->client->send(entry->client, entry->cmd_code, entry->data);

	entry->stream->on_read(entry->stream, client_read, entry);
}

void rcios_client_dump_gateway(u_int mod_id, char *uri, rcios_client_rpc_cb cb)
{
	rcios_client_entry_t *entry;

	INIT(entry,
		.client = rcios_client_create(mod_id, uri),
		.cmd_code = IPSECD_CMD_DUMP_GATEWAY,
		.data = chunk_from_str(RC_CMD_SET_GATEWAY_PAYLOAD),
		.cb = cb,
	);
	entry->stream = ((private_rcios_client_t *)entry->client)->stream,

	entry->client->send(entry->client, entry->cmd_code, entry->data);

	entry->stream->on_read(entry->stream, client_read, entry);
}