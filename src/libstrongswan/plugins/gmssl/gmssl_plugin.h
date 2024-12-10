#ifndef GMSSL_PLUGIN_H_
#define GMSSL_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct gmssl_plugin_t gmssl_plugin_t;

/**
 * 
 */
struct gmssl_plugin_t
{
    /**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif