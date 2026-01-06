#include "rcios_config.h"

#include <collections/hashtable.h>
#include <threading/rwlock.h>
#include <threading/rwlock_condvar.h>

typedef struct private_rcios_config_t private_rcios_config_t;

struct private_rcios_config_t
{
	rcios_config_t public;
	rcios_dispatcher_t *dispatcher;
	hashtable_t *conns;
	rwlock_t *lock;
	rwlock_condvar_t *condvar;
};

CALLBACK(destroy_conn, void,
	peer_cfg_t *cfg, const void *key)
{
	cfg->destroy(cfg);
}

static void rcios_config_register_cmd(private_rcios_config_t *this,
								rcios_cmd_e cmd, rcios_command_cb_t cb, bool reg)
{
	this->dispatcher->manage_command(this->dispatcher, cmd, reg ? cb : NULL, this);
}

CALLBACK(rc_cmd_set_gateway, int,
	private_rcios_config_t *this, u_int client_id, chunk_t data, array_t **response)
{
	DBG1(DBG_DMN, "[%s][%d] client_id : %d, data : %B", __func__, __LINE__, client_id, &data);
	return 0;
}

CALLBACK(rc_cmd_dump_gateway, int,
	private_rcios_config_t *this, u_int client_id, chunk_t data, array_t **presponse)
{
	DBG1(DBG_DMN, "[%s][%d] client_id : %d, data : %B", __func__, __LINE__, client_id, &data);
	int count = 4;
	array_t *response = array_create(sizeof(chunk_t), count);
	for (int i = 0; i < count; i++)
	{
		chunk_t one_res = chunk_alloc(16);
		snprintf(one_res.ptr, 16, "this's %dth dump", i + 1);
		array_insert(response, i, &one_res);
	}
	*presponse = response;
	return 0;
}

static void rcios_config_register_cmds(private_rcios_config_t *this, bool reg)
{
	rcios_config_register_cmd(this, IPSECD_CMD_SET_GATEWAY, rc_cmd_set_gateway, reg);
	rcios_config_register_cmd(this, IPSECD_CMD_DUMP_GATEWAY, rc_cmd_dump_gateway, reg);
}

METHOD(rcios_config_t, destroy, void,
	private_rcios_config_t *this)
{
	rcios_config_register_cmds(this, FALSE);
	this->conns->destroy_function(this->conns, destroy_conn);
	this->condvar->destroy(this->condvar);
	this->lock->destroy(this->lock);
	free(this);
}

rcios_config_t *rcios_config_create(rcios_dispatcher_t *dispatcher)
{
	private_rcios_config_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.dispatcher = dispatcher,
		.conns = hashtable_create(hashtable_hash_str, hashtable_equals_str, 32),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.condvar = rwlock_condvar_create(),
	);

	rcios_config_register_cmds(this, TRUE);

	return &this->public;
}