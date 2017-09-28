#include <assert.h>
#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
#include <errno.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

bool wire_sync_write(int fd, const void *msg TAKES)
{
	wire_len_t len = tal_len(msg);
	bool ret;

	assert(tal_len(msg) < WIRE_LEN_LIMIT);
	ret = write_all(fd, &len, sizeof(len))
		&& write_all(fd, msg, len);

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
	if (len >= WIRE_LEN_LIMIT) {
		errno = E2BIG;
		return NULL;
	}
	msg = tal_arr(ctx, u8, len);
	if (!read_all(fd, msg, len))
		return tal_free(msg);
	return msg;
}
