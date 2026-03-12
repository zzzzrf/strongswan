#include "rcios_socket.h"
#include "rcios_dispatcher.h"

#include <bio/bio_reader.h>
#include <bio/bio_writer.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <collections/hashtable.h>

typedef struct private_rcios_dispatcher_t private_rcios_dispatcher_t;

struct private_rcios_dispatcher_t
{
	rcios_dispatcher_t public;
	rcios_socket_t *socket;
	hashtable_t *cmds;
	mutex_t *mutex;
	condvar_t *cond;
};

typedef struct {
	char *name;
	/** callback for command */
	rcios_command_cb_t cb;
	/** user data to pass to callback */
	void *user;
	/** command currently in use? */
	u_int uses;
} command_t;

typedef struct {
	private_rcios_dispatcher_t *this;
	command_t *cmd;
	array_t *response;
	u_int id;
} response_data_t;

CALLBACK(rcios_dispatcher_do_reply, void,
	chunk_t *payload, int idx, response_data_t *this)
{
	this->this->socket->send(this->this->socket, this->id, 0, *payload);
	chunk_free(payload);
}

CALLBACK(inbound, void,
	private_rcios_dispatcher_t *this, u_int id, u_int cmd_code, chunk_t data)
{
	uint16_t ret = -1;
	command_t *cmd;
	response_data_t *release;

	this->mutex->lock(this->mutex);
	cmd = this->cmds->get(this->cmds, enum_to_name(rcios_ipsecd_cmd_names, cmd_code));
	if (cmd)
		cmd->uses++;
	this->mutex->unlock(this->mutex);

	// DBG1(DBG_DMN, "recv %N cmd, data : %B", rcios_ipsecd_cmd_names, cmd_code, &data);

	if (cmd)
	{
		INIT(release,
			.this = this,
			.cmd = cmd,
			.id = id);

		ret = cmd->cb(cmd->user, id, data, &release->response);
		array_destroy_function(release->response, (array_callback_t)rcios_dispatcher_do_reply, release);
		free(release);
		this->mutex->lock(this->mutex);
		if (--cmd->uses == 0)
			this->cond->broadcast(this->cond);
		this->mutex->unlock(this->mutex);
	}
	else
	{
		DBG1(DBG_DMN, "unknown %d cmd_code", cmd_code);
	}
	this->socket->send(this->socket, id, ret, chunk_empty);
}

CALLBACK(connect_, void,
	private_rcios_dispatcher_t *this, u_int id)
{
	DBG2(DBG_DMN, "rcios client %u connected", id);
}

CALLBACK(disconnect, void,
	private_rcios_dispatcher_t *this, u_int id)
{
	DBG2(DBG_DMN, "rcios client %u disconnected", id);
}

METHOD(rcios_dispatcher_t, destroy, void,
	private_rcios_dispatcher_t *this)
{
	DESTROY_IF(this->socket);
	this->mutex->destroy(this->mutex);
	this->cond->destroy(this->cond);
	this->cmds->destroy(this->cmds);
	free(this);
}

METHOD(rcios_dispatcher_t, manage_command, void,
	private_rcios_dispatcher_t *this, rcios_cmd_e cmd,
	rcios_command_cb_t cb, void *user)
{
	command_t *command = NULL;

	this->mutex->lock(this->mutex);
	if (cb)
	{
		INIT(command,
			.name = strdup(enum_to_name(rcios_ipsecd_cmd_names, cmd)),
			.cb = cb,
			.user = user,
		);
		DBG1(DBG_DMN, "register cmd : %s", command->name);
		command = this->cmds->put(this->cmds, command->name, command);
	}
	else
	{
		command = this->cmds->remove(this->cmds, enum_to_name(rcios_ipsecd_cmd_names, cmd));
	}
	if (command)
	{
		while (command->uses)
		{
			this->cond->wait(this->cond, this->mutex);
		}
		free(command->name);
		free(command);
	}
	this->mutex->unlock(this->mutex);
}

rcios_dispatcher_t *rcios_dispatcher_create(char *uri)
{
	private_rcios_dispatcher_t *this;
	
	INIT(this,
		.public = {
			.manage_command = _manage_command,
			.destroy = _destroy,
		},
		.cmds = hashtable_create(hashtable_hash_str, hashtable_equals_str, 1),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.cond = condvar_create(CONDVAR_TYPE_DEFAULT),
	);

	this->socket = rcios_socket_create(uri, inbound, connect_, disconnect, this);
	if (!this->socket)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}