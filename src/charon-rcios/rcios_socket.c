#include "rcios_socket.h"

#include <errno.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

typedef struct private_rcios_socket_t private_rcios_socket_t;

struct private_rcios_socket_t
{
	rcios_socket_t public;
	stream_service_t *service;
	rcios_inbound_cb_t inbound;
	rcios_disconnect_cb_t disconnect;
	rcios_connect_cb_t connect;

	void *user;
	u_int nextid;

	linked_list_t *connections;
	mutex_t *mutex;
};

typedef struct {
	/* reference to socket instance */
	private_rcios_socket_t *this;
	/** connection identifier of entry */
	u_int id;
} entry_selector_t;

typedef struct {
	/** bytes of length header sent/received */
	u_char hdrlen;
	/** bytes of length header */
	char hdr[sizeof(struct rcios_rpc_hdr_t)];
	/** send/receive buffer on heap */
	chunk_t buf;
	/** bytes sent/received in buffer */
	uint32_t done;
} msg_buf_t;

typedef struct {
	/** reference to socket */
	private_rcios_socket_t *this;
	/** associated stream */
	stream_t *stream;
	/** queued messages to send, as msg_buf_t pointers */
	array_t *out;
	/** input message buffer */
	msg_buf_t in;
	/** queued input messages to process, as chunk_t */
	array_t *queue;
	/** do we have job processing input queue? */
	bool has_processor;
	/** is this client disconnecting */
	bool disconnecting;
	/** client connection identifier */
	u_int id;
	/** any users reading over this connection? */
	int readers;
	/** any users writing over this connection? */
	int writers;
	/** any users using this connection at all? */
	int users;
	/** condvar to wait for usage  */
	condvar_t *cond;
} entry_t;

CALLBACK(destroy_entry, void,
	entry_t *entry)
{
	msg_buf_t *out;
	chunk_t chunk;

	entry->stream->destroy(entry->stream);
	entry->this->disconnect(entry->this->user, entry->id);
	entry->cond->destroy(entry->cond);

	while (array_remove(entry->out, ARRAY_TAIL, &out))
	{
		chunk_clear(&out->buf);
		free(out);
	}
	array_destroy(entry->out);
	while (array_remove(entry->queue, ARRAY_TAIL, &chunk))
	{
		chunk_clear(&chunk);
	}
	array_destroy(entry->queue);
	chunk_clear(&entry->in.buf);
	free(entry);
}

static entry_t* find_entry(private_rcios_socket_t *this, stream_t *stream,
						   u_int id, bool reader, bool writer)
{
	enumerator_t *enumerator;
	entry_t *entry, *found = NULL;
	bool candidate = TRUE;
	
	this->mutex->lock(this->mutex);
	while (candidate && !found)
	{
		candidate = FALSE;
		enumerator = this->connections->create_enumerator(this->connections);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (stream)
			{
				if (entry->stream != stream)
				{
					continue;
				}
			}
			else
			{
				if (entry->id != id)
				{
					continue;
				}
			}
			if (entry->disconnecting)
			{
				entry->cond->signal(entry->cond);
				continue;
			}
			candidate = TRUE;

			if ((reader && entry->readers) ||
				(writer && entry->writers))
			{
				entry->cond->wait(entry->cond, this->mutex);
				break;
			}
			if (reader)
			{
				entry->readers++;
			}
			if (writer)
			{
				entry->writers++;
			}
			entry->users++;
			found = entry;
			break;
		}
		enumerator->destroy(enumerator);
	}
	this->mutex->unlock(this->mutex);

	return found;
}

static entry_t* remove_entry(private_rcios_socket_t *this, u_int id)
{
	enumerator_t *enumerator;
	entry_t *entry, *found = NULL;
	bool candidate = TRUE;

	this->mutex->lock(this->mutex);
	while (candidate && !found)
	{
		candidate = FALSE;
		enumerator = this->connections->create_enumerator(this->connections);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (entry->id == id)
			{
				candidate = TRUE;
				if (entry->readers || entry->writers || entry->users)
				{
					entry->cond->wait(entry->cond, this->mutex);
					break;
				}
				this->connections->remove_at(this->connections, enumerator);
				entry->cond->broadcast(entry->cond);
				found = entry;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	this->mutex->unlock(this->mutex);

	return found;
}

static void put_entry(private_rcios_socket_t *this, entry_t *entry,
					  bool reader, bool writer)
{
	this->mutex->lock(this->mutex);
	if (reader)
		entry->readers--;
	if (writer)
		entry->writers--;
	entry->users--;
	entry->cond->signal(entry->cond);
	this->mutex->unlock(this->mutex);
}

static bool do_read(private_rcios_socket_t *this, entry_t *entry,
					stream_t *stream, char *errmsg, size_t errlen)
{
	uint32_t msglen;
	ssize_t len;

	while (entry->in.hdrlen < sizeof(entry->in.hdr))
	{
		len = stream->read(stream, entry->in.hdr + entry->in.hdrlen,
						   sizeof(entry->in.hdr) - entry->in.hdrlen, FALSE);
		if (len == 0)
		{
			return FALSE;
		}
		if (len < 0)
		{
			if (errno == EWOULDBLOCK)
			{
				return TRUE;
			}
			snprintf(errmsg, errlen, "vici header read error: %s",
					 strerror(errno));
			return FALSE;
		}
		entry->in.hdrlen += len;
		if (entry->in.hdrlen == sizeof(entry->in.hdr))
		{
			rcios_rpc_hdr_t *phdr = (rcios_rpc_hdr_t *)entry->in.hdr;
			msglen = phdr->datalen;
			if (msglen > RCIOS_MESSAGE_SIZE_MAX)
			{
				snprintf(errmsg, errlen, "rcios message length %u exceeds %u "
						 "bytes limit, ignored", msglen, RCIOS_MESSAGE_SIZE_MAX);
				return FALSE;
			}
			entry->in.buf = chunk_alloc(msglen);
			// DBG1(DBG_DMN, "recv %d cmd, header : %b", phdr->cmd_code, phdr, sizeof(rcios_rpc_hdr_t));
		}
	}

	while (entry->in.buf.len > entry->in.done)
	{
		len = stream->read(stream, entry->in.buf.ptr + entry->in.done,
						   entry->in.buf.len - entry->in.done, FALSE);
		if (len == 0)
		{
			snprintf(errmsg, errlen, "premature rcios disconnect");
			return FALSE;
		}
		if (len < 0)
		{
			if (errno == EWOULDBLOCK)
			{
				return TRUE;
			}
			snprintf(errmsg, errlen, "rcios read error: %s", strerror(errno));
			return FALSE;
		}
		entry->in.done += len;
	}

	return TRUE;
}

CALLBACK(disconnect_async, job_requeue_t,
	entry_selector_t *sel)
{
	entry_t *entry;

	entry = remove_entry(sel->this, sel->id);
	if (entry)
	{
		destroy_entry(entry);
	}
	return JOB_REQUEUE_NONE;
}

static void disconnect(private_rcios_socket_t *this, u_int id)
{
	entry_selector_t *sel;

	INIT(sel,
		.this = this,
		.id = id,
	);

	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create(disconnect_async, sel, free, NULL));
}

static void destroy_request_chunk(chunk_t *chunk)
{
	chunk_clear(chunk);
	free(chunk);
}

CALLBACK(process_queue, job_requeue_t,
	entry_selector_t *sel)
{
	rcios_rpc_hdr_t *hdr;
	entry_t *entry;
	chunk_t *chunk;
	bool found;
	u_int id;

	while (TRUE)
	{
		entry = find_entry(sel->this, NULL, sel->id, TRUE, FALSE);
		if (!entry)
		{
			break;
		}

		INIT(chunk);
		found = array_remove(entry->queue, ARRAY_HEAD, chunk);
		if (!found)
		{
			entry->has_processor = FALSE;
		}
		id = entry->id;
		put_entry(sel->this, entry, TRUE, FALSE);
		if (!found)
		{
			free(chunk);
			break;
		}
		hdr = (rcios_rpc_hdr_t *)entry->in.hdr;
		thread_cleanup_push((void*)destroy_request_chunk, chunk);
		sel->this->inbound(sel->this->user, id, hdr->cmd_code, *chunk);
		thread_cleanup_pop(TRUE);
	}
	return JOB_REQUEUE_NONE;
}

CALLBACK(on_read, bool,
	private_rcios_socket_t *this, stream_t *stream)
{
	char errmsg[256] = "";
	entry_selector_t *sel;
	entry_t *entry;
	bool ret = FALSE;

	entry = find_entry(this, stream, 0, TRUE, FALSE);
	if (entry)
	{
		ret = do_read(this, entry, stream, errmsg, sizeof(errmsg));
		if (!ret)
		{
			entry->disconnecting = TRUE;
			disconnect(this, entry->id);
		}
		else if (entry->in.hdrlen == sizeof(entry->in.hdr) &&
				 entry->in.buf.len == entry->in.done)
		{
			array_insert(entry->queue, ARRAY_TAIL, &entry->in.buf);
			entry->in.buf = chunk_empty;
			entry->in.hdrlen = entry->in.done = 0;

			if (!entry->has_processor)
			{
				INIT(sel,
					.this = this,
					.id = entry->id,
				);
				lib->processor->queue_job(lib->processor,
							(job_t*)callback_job_create(process_queue, sel,
											free, callback_job_cancel_thread));
				entry->has_processor = TRUE;
			}
		}
		put_entry(this, entry, TRUE, FALSE);

		if (!ret && errmsg[0])
		{
			DBG1(DBG_DMN, "%s", errmsg);
		}
	}

	return ret;
}

CALLBACK(on_accept, bool,
	private_rcios_socket_t *this, stream_t *stream)
{
	entry_t *entry;
	u_int id;

	id = ref_get(&this->nextid);

	INIT(entry,
		.this = this,
		.stream = stream,
		.id = id,
		.out = array_create(0, 0),
		.queue = array_create(sizeof(chunk_t), 0),
		.cond = condvar_create(CONDVAR_TYPE_DEFAULT),
		.readers = 1,
		.users = 1,
	);

	this->mutex->lock(this->mutex);
	this->connections->insert_last(this->connections, entry);
	this->mutex->unlock(this->mutex);

	stream->on_read(stream, on_read, this);

	put_entry(this, entry, TRUE, FALSE);

	this->connect(this->user, id);

	return TRUE;
}

METHOD(rcios_socket_t, destroy, void,
	private_rcios_socket_t *this)
{
	DESTROY_IF(this->service);
	this->connections->destroy(this->connections);
	this->mutex->destroy(this->mutex);
	free(this);
}

static bool do_write(private_rcios_socket_t *this, entry_t *entry,
					 stream_t *stream, char *errmsg, size_t errlen, bool block)
{
	msg_buf_t *out;
	ssize_t len;

	while (array_get(entry->out, ARRAY_HEAD, &out))
	{
		/* write header */
		while (out->hdrlen < sizeof(out->hdr))
		{
			len = stream->write(stream, out->hdr + out->hdrlen,
								sizeof(out->hdr) - out->hdrlen, block);
			if (len == 0)
			{
				return FALSE;
			}
			if (len < 0)
			{
				if (errno == EWOULDBLOCK)
				{
					return TRUE;
				}
				snprintf(errmsg, errlen, "rcios header write error: %s",
						 strerror(errno));
				return FALSE;
			}
			out->hdrlen += len;
		}
		DBG2(DBG_DMN, "write to %d client, header : %b", entry->id, out->hdr, out->hdrlen);

		/* write buffer buffer */
		while (out->buf.len > out->done)
		{
			len = stream->write(stream, out->buf.ptr + out->done,
								out->buf.len - out->done, block);
			if (len == 0)
			{
				snprintf(errmsg, errlen, "premature rcios disconnect");
				return FALSE;
			}
			if (len < 0)
			{
				if (errno == EWOULDBLOCK)
				{
					return TRUE;
				}
				snprintf(errmsg, errlen, "rcios write error: %s", strerror(errno));
				return FALSE;
			}
			out->done += len;
		}
		DBG2(DBG_DMN, "write to %d client, data : %b", entry->id, out->buf.ptr, out->done);
		if (array_remove(entry->out, ARRAY_HEAD, &out))
		{
			chunk_clear(&out->buf);
			free(out);
		}
	}
	return TRUE;
}

CALLBACK(on_write, bool,
	private_rcios_socket_t *this, stream_t *stream)
{
	char errmsg[256] = "";
	entry_t *entry;
	bool ret = FALSE;

	entry = find_entry(this, stream, 0, FALSE, TRUE);
	if (entry)
	{
		ret = do_write(this, entry, stream, errmsg, sizeof(errmsg), FALSE);
		if (ret)
		{
			/* unregister if we have no more messages to send */
			ret = array_count(entry->out) != 0;
		}
		else
		{
			entry->disconnecting = TRUE;
			disconnect(entry->this, entry->id);
		}
		put_entry(this, entry, FALSE, TRUE);

		if (!ret && errmsg[0])
		{
			DBG1(DBG_DMN, "%s", errmsg);
		}
	}

	return ret;
}

CALLBACK(enable_writer, job_requeue_t,
	entry_selector_t *sel)
{
	entry_t *entry;

	entry = find_entry(sel->this, NULL, sel->id, FALSE, FALSE);
	if (entry)
	{
		entry->stream->on_write(entry->stream, on_write, sel->this);
		put_entry(sel->this, entry, FALSE, FALSE);
	}
	return JOB_REQUEUE_NONE;
}

METHOD(rcios_socket_t, send_, void,
	private_rcios_socket_t *this, u_int id, uint16_t ret_code, chunk_t msg)
{
	if (msg.len <= RCIOS_MESSAGE_SIZE_MAX)
	{
		rcios_rpc_hdr_t *phdr;
		entry_selector_t *sel;
		msg_buf_t *out;
		entry_t *entry;

		entry = find_entry(this, NULL, id, FALSE, TRUE);
		if (entry)
		{
			INIT(out,
				.buf = chunk_clone(msg),
			);

			memcpy(out->hdr, entry->in.hdr, sizeof(rcios_rpc_hdr_t));
			phdr = (rcios_rpc_hdr_t *)out->hdr;
			phdr->cmd_code = ret_code;
			phdr->datalen = msg.len;
			IOS_RPC_SET_FLAGS(phdr, phdr->datalen ? IOS_RPC_DATA : IOS_RPC_ACK);

			array_insert(entry->out, ARRAY_TAIL, out);
			if (array_count(entry->out) == 1)
			{	/* asynchronously re-enable on_write callback when we get data */
				INIT(sel,
					.this = this,
					.id = entry->id,
				);
				lib->processor->queue_job(lib->processor,
							(job_t*)callback_job_create(enable_writer,
														sel, free, NULL));
			}
			put_entry(this, entry, FALSE, TRUE);
		}
		else
		{
			DBG1(DBG_DMN, "rcios connection %u unknown", id);
			chunk_clear(&msg);
		}
	}
	else
	{
		DBG1(DBG_DMN, "rcios message size %zu exceeds maximum size of %u, "
			 "discarded", msg.len, RCIOS_MESSAGE_SIZE_MAX);
		chunk_clear(&msg);
	}
}

rcios_socket_t *rcios_socket_create(char *uri, rcios_inbound_cb_t inbound,
								  rcios_connect_cb_t connect,
								  rcios_disconnect_cb_t disconnect, void *user)
{
	private_rcios_socket_t *this;

	INIT(this,
		.public = {
			.send = _send_,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.connections = linked_list_create(),
		.inbound = inbound,
		.connect = connect,
		.disconnect = disconnect,
		.user = user,
	);

	this->service = lib->streams->create_service(lib->streams, uri, 3);
	if (!this->service)
	{
		DBG1(DBG_DMN, "creating rcios socket failed");
		destroy(this);
		return NULL;
	}
	this->service->on_accept(this->service, on_accept, this,
							 JOB_PRIO_CRITICAL, 0);
	return &this->public;
}