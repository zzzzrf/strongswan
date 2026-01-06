#ifndef __RCIOS_CLIENT_H__
#define __RCIOS_CLIENT_H__

#include "rcios_socket.h"

typedef struct rcios_client_t rcios_client_t;
typedef struct rcios_client_entry_t rcios_client_entry_t;
typedef int (*rcios_client_rpc_cb)(rcios_client_entry_t *e, rcios_rpc_hdr_t *phdr, chunk_t msg);

struct rcios_client_t
{
	bool (*send)(rcios_client_t *this, u_int cmd_code, chunk_t data);
	void (*on_read)(rcios_client_t *this, stream_cb_t cb, void *data);
	void (*destroy)(rcios_client_t *this);
};

typedef struct rcios_client_entry_t
{
	rcios_client_t *client;
	stream_t *stream;
	u_int cmd_code;
	chunk_t data;
	rcios_client_rpc_cb cb;
}rcios_client_entry_t;

rcios_client_t *rcios_client_create(u_int mod_id, char *uri);
void rcios_client_set_gateway(u_int mod_id, char *uri, rcios_client_rpc_cb cb);
void rcios_client_dump_gateway(u_int mod_id, char *uri, rcios_client_rpc_cb cb);
#endif