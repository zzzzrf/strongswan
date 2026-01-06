#include <library.h>
#include <daemon.h>
#include <errno.h>
#include <unistd.h>

/* 结合 leak-detective 检测是否存在内存泄露 */
// #define __CHARON_RCIOS_TEST_AND_EXIT__ 1

#include "charon_rcios.h"

#ifdef __CHARON_RCIOS_TEST_AND_EXIT__
#include "rcios_client.h"
#endif

rcios_charon_t *rcios_charon = NULL;
extern void (*dbg) (debug_t group, level_t level, char *fmt, ...);

static void dbg_stderr(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	if (level <= 1)
	{
		va_start(args, fmt);
		fprintf(stderr, "00[%N] ", debug_names, group);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

#ifndef __CHARON_RCIOS_TEST_AND_EXIT__
static int run()
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, NULL);

	while (TRUE)
	{
		int sig;

		sig = sigwaitinfo(&set, NULL);
		if (sig == -1)
		{
			if (errno == EINTR)
			{	/* ignore signals we didn't wait for */
				continue;
			}
			DBG1(DBG_DMN, "waiting for signal failed: %s", strerror(errno));
			return SS_RC_INITIALIZATION_FAILED;
		}
		switch (sig)
		{
			case SIGHUP:
			{
				DBG1(DBG_DMN, "signal of type SIGHUP received. Reloading "
					 "configuration");
				if (lib->settings->load_files(lib->settings, lib->conf, FALSE))
				{
					charon->load_loggers(charon);
					lib->plugins->reload(lib->plugins, NULL);
				}
				else
				{
					DBG1(DBG_DMN, "reloading config failed, keeping old");
				}
				break;
			}
			case SIGTERM:
			{
				DBG1(DBG_DMN, "SIGTERM received, shutting down");
				charon->bus->alert(charon->bus, ALERT_SHUTDOWN_SIGNAL, sig);
				return 0;
			}
		}
	}
}

#else

static int test_request_cmd_cb(rcios_client_entry_t *e, rcios_rpc_hdr_t *phdr, chunk_t msg)
{
	DBG1(DBG_APP, "[%s]mod_id : %d, ret : %d, msg : %B", __func__, phdr->mod_id, phdr->cmd_code, &msg);
	return 0;
}

static int test_dump_cmd_cb(rcios_client_entry_t *e, rcios_rpc_hdr_t *phdr, chunk_t msg)
{
	DBG1(DBG_APP, "[%s]mod_id : %d, ret : %d, msg : %B", __func__, phdr->mod_id, phdr->cmd_code, &msg);
	return 0;
}
#endif

rcios_charon_t *rcios_charon_init(char *uri)
{

	INIT(rcios_charon,
		.dispatcher = rcios_dispatcher_create(uri),
	);

	rcios_charon->config = rcios_config_create(rcios_charon->dispatcher);

	return rcios_charon;
}

void rcios_charon_deinit()
{
	rcios_charon->config->destroy(rcios_charon->config);
	rcios_charon->dispatcher->destroy(rcios_charon->dispatcher);
	free(rcios_charon);
	rcios_charon = NULL;
	return ;
}

int main(int argc, char *argv[])
{
	int group;
	level_t levels[DBG_MAX];
	struct sigaction action;

	dbg = dbg_stderr;
	atexit(library_deinit);
	if (!library_init(NULL, "charon-rcios"))
	{
		return -1;
	}
	atexit(libcharon_deinit);
	if (!libcharon_init())
	{
		return -1;
	}
	for (group = 0; group < DBG_MAX; group++)
	{
		levels[group] = LEVEL_SILENT;
	}
	levels[DBG_DMN] = levels[DBG_APP] = LEVEL_CTRL;
	charon->set_default_loggers(charon, levels, TRUE);
	charon->load_loggers(charon);

	rcios_charon = rcios_charon_init(CHARON_RCIOS_PATH);
	atexit(rcios_charon_deinit);

	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	// sigaddset(&action.sa_mask, SIGINT);
	sigaddset(&action.sa_mask, SIGTERM);
	sigaddset(&action.sa_mask, SIGHUP);

	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
	pthread_sigmask(SIG_SETMASK, &action.sa_mask, NULL);
	
	lib->processor->set_threads(lib->processor, 4);
#ifndef __CHARON_RCIOS_TEST_AND_EXIT__
	run();
#else
	sleep(1);
	rcios_client_set_gateway(1, CHARON_RCIOS_PATH, test_request_cmd_cb);
	sleep(1);
	rcios_client_dump_gateway(2, CHARON_RCIOS_PATH, test_dump_cmd_cb);
	sleep(1);
#endif
	return 0;
}
