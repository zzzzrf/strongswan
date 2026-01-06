#ifndef __RCIOS_CMDS_H__
#define __RCIOS_CMDS_H__

#include <utils/utils.h>

typedef enum rcios_cmd_e rcios_cmd_e;

enum rcios_cmd_e
{
	IPSECD_CMD_SET_GATEWAY,
	IPSECD_CMD_SET_TYPE,
	IPSECD_CMD_SET_MODE,
	IPSECD_CMD_DUMP_GATEWAY,
};

extern enum_name_t *rcios_ipsecd_cmd_names;

#endif