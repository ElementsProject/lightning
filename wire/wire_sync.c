#include "config.h"
#include <assert.h>
#include <ccan/read_write_all/read_write_all.h>
#include <errno.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

bool wire_sync_write(int fd, const void *msg TAKES)
{
	wire_len_t hdr = cpu_to_wirelen(tal_bytelen(msg));
	bool ret;

	assert(tal_bytelen(msg) < WIRE_LEN_LIMIT);
	ret = write_all(fd, &hdr, sizeof(hdr))
		&& write_all(fd, msg, tal_count(msg));

	if (taken(msg))
		tal_free(msg);
	return ret;
}

u8 *wire_sync_read(const tal_t *ctx, int fd)
{
	wire_len_t len;
	u8 *msg;

	if (!read_all(fd, &len, sizeof(len)))
		return NULL;
	if (wirelen_to_cpu(len) >= WIRE_LEN_LIMIT) {
		errno = E2BIG;
		return NULL;
	}
	msg = tal_arr(ctx, u8, wirelen_to_cpu(len));
	if (!read_all(fd, msg, wirelen_to_cpu(len)))
		return tal_free(msg);
	return msg;
}
