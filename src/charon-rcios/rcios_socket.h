#ifndef __RCIOS_SOCKET_H__
#define __RCIOS_SOCKET_H__

#include <library.h>

#define RCIOS_MESSAGE_SIZE_MAX	4096

typedef struct rcios_rpc_hdr_t rcios_rpc_hdr_t;
typedef struct rcios_socket_t rcios_socket_t;

struct rcios_rpc_hdr_t
{
	u_int mod_id;
	u_char flags;
	u_char magic[7];
	uint16_t cmd_code;
	uint16_t datalen;
	u_char data[0];
};

#define IOS_RPC_VERSION2	2
#define IOS_RPC_REQ	1
#define IOS_RPC_DATA 2
#define IOS_RPC_ACK 4
#define IOS_RPC_NOTIFY 8

#define IOS_RPC_GET_VERSION(phdr) (((phdr)->flags) >> 4)
#define IOS_RPC_GET_TYPE(phdr) (((phdr)->flags) & 0xf)
#define IOS_RPC_SET_FLAGS(phdr, type) (((phdr)->flags) = ((IOS_RPC_VERSION2 << 4) + (type)))

struct rcios_socket_t
{
	void (*send)(rcios_socket_t *this, u_int id, uint16_t ret_code, chunk_t data);
	void (*destroy)(rcios_socket_t *this);
};

typedef void (*rcios_inbound_cb_t)(void *user, u_int id, u_int cmd_code, chunk_t data);

typedef void (*rcios_connect_cb_t)(void *user, u_int id);

typedef void (*rcios_disconnect_cb_t)(void *user, u_int id);

rcios_socket_t *rcios_socket_create(char *uri, rcios_inbound_cb_t inbound,
								  rcios_connect_cb_t connect,
								  rcios_disconnect_cb_t disconnect, void *user);

#endif