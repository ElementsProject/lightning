#include "wire/wire_sync.h"
#include <assert.h>
#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>

bool wire_sync_write(int fd, const void *msg TAKES)
{
	be16 be_len = cpu_to_be16(tal_count(msg));
	bool ret;

	assert(be16_to_cpu(be_len) == tal_count(msg));
	ret = write_all(fd, &be_len, sizeof(be_len))
		&& write_all(fd, msg, tal_count(msg));

	if (taken(msg))
		tal_free(msg);
	return ret;
}

u8 *wire_sync_read(const tal_t *ctx, int fd)
{
	be16 be_len;
	u8 *msg;

	if (!read_all(fd, &be_len, sizeof(be_len)))
		return NULL;
	msg = tal_arr(ctx, u8, be16_to_cpu(be_len));
	if (!read_all(fd, msg, be16_to_cpu(be_len)))
		return tal_free(msg);
	return msg;
}
