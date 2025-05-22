#include "config.h"
#include <common/per_peer_state.h>
#include <common/read_peer_msg.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{
}

void run(const u8 *data, size_t size)
{
    struct per_peer_state pps = { .peer_fd = -1 };
    u8 *buf = tal_dup_arr(NULL, u8, data, size, 0);
    handle_peer_error_or_warning(&pps, buf);

    tal_free(buf);
}