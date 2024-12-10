#include <stdio.h>
#include <unistd.h>

#include "bus/listeners/listener.h"
#include "library.h"
#include "daemon.h"
#include "bus/listeners/logger.h"
#include "utils/debug.h"

static level_t get_level(logger_t *this, debug_t group)
{
    level_t dbg_level[DBG_MAX];
    debug_t g;
    for (g = DBG_DMN; g < DBG_MAX; g++)
        dbg_level[g] = LEVEL_PRIVATE;

    dbg_level[DBG_JOB] = LEVEL_CTRL;

    return dbg_level[group];
} 

static void _log_(logger_t *this, debug_t group, level_t level, int thread,
				ike_sa_t *ike_sa, const char *message)
{
    fprintf(stderr, "[%N%d] ", debug_names, group, level);
    fprintf(stderr, "%s\n", message);
    return ;
}

logger_t logger = {
    .get_level = get_level,
    .log = _log_,
};

static void bus_test_init(void)
{
    library_init(NULL, "mybus");
    libcharon_init();

    charon->bus->add_logger(charon->bus, &logger);
    return ;
}

static void bus_test_run(void)
{
    lib->processor->set_threads(lib->processor, 4);
    return ;
}

int main(int argc, char **argv)
{
    bus_test_init();

    bus_test_run();

    pause();
    return 0;
}