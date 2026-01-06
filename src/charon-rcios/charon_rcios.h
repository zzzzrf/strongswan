#ifndef __CHARON_RCIOS_H__
#define __CHARON_RCIOS_H__

#include "rcios_dispatcher.h"
#include "rcios_config.h"

typedef struct rcios_charon_t rcios_charon_t;

struct rcios_charon_t
{
	rcios_dispatcher_t *dispatcher;
	rcios_config_t *config;
};

extern rcios_charon_t *rcios_charon;

rcios_charon_t *rcios_charon_init(char *uri);
void rcios_charon_deinit();
#endif