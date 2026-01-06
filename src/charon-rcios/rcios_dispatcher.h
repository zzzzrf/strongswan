#ifndef __RCIOS_DISPATCHER_H__
#define __RCIOS_DISPATCHER_H__

#include <utils/chunk.h>
#include <collections/array.h>
#include "rcios_cmds.h"

#define CHARON_RCIOS_PATH "unix:///tmp/charon.rcios"

typedef struct rcios_dispatcher_t rcios_dispatcher_t;

typedef int (*rcios_command_cb_t)(void *this, u_int client_id, chunk_t data, array_t **response);

struct rcios_dispatcher_t
{
	void (*manage_command)(rcios_dispatcher_t *this, rcios_cmd_e cmd,
						   rcios_command_cb_t cb, void *user);
	void (*destroy)(rcios_dispatcher_t *this);
};

extern rcios_dispatcher_t *rcios;

rcios_dispatcher_t *rcios_dispatcher_create(char *uri);

#endif