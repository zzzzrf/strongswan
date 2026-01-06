#ifndef __RCIOS_CONFIG_H__
#define __RCIOS_CONFIG_H__

#include <config/backend.h>

#include "rcios_dispatcher.h"

typedef struct rcios_config_t rcios_config_t;

struct rcios_config_t
{
	backend_t backend;
	void (*destroy)(rcios_config_t *this);
};

rcios_config_t *rcios_config_create(rcios_dispatcher_t *dispatcher);

#endif