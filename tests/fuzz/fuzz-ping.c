#include "config.h"
#include <common/utils.h>
#include <common/ping.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
    u8 *pong;
    u8 *buf = tal_dup_arr(tmpctx, u8, data, size, 0);
    check_ping_make_pong(tmpctx, buf, &pong);

    clean_tmpctx();
}