#include <ccan/crc/crc.h>
#include <ccan/endian/endian.h>
#include <common/gossip_store.h>
#include <common/status.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

u8 *gossip_store_read(const tal_t *ctx, int gossip_store_fd, u64 offset)
{
	beint32_t hdr[2];
	u32 msglen, checksum;
	u8 *msg;

	if (offset == 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't access offset %"PRIu64,
			      offset);
	if (pread(gossip_store_fd, hdr, sizeof(hdr), offset) != sizeof(hdr)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read hdr offset %"PRIu64
			      ": %s",
			      offset, strerror(errno));
	}

	msglen = be32_to_cpu(hdr[0]);
	checksum = be32_to_cpu(hdr[1]);
	msg = tal_arr(ctx, u8, msglen);
	if (pread(gossip_store_fd, msg, msglen, offset + sizeof(hdr)) != msglen)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read len %u offset %"PRIu64,
			      msglen, offset);

	if (checksum != crc32c(0, msg, msglen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: bad checksum offset %"PRIu64,
			      offset);

	return msg;
}

