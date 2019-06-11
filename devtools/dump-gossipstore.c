#include <ccan/crc32c/crc32c.h>
#include <ccan/err/err.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <fcntl.h>
#include <common/gossip_store.h>
#include <gossipd/gen_gossip_peerd_wire.h>
#include <gossipd/gen_gossip_store.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>

int main(int argc, char *argv[])
{
	int fd;
	u8 version;
	struct gossip_hdr hdr;
	size_t off;

	setup_locale();

	if (argc > 2)
		errx(1, "Need the filename of a gossip store, or stdin");

	if (argc == 2) {
		fd = open(argv[1], O_RDONLY);
		if (fd < 0)
			err(1, "Opening %s", argv[1]);
	} else
		fd = STDIN_FILENO;

	if (read(fd, &version, sizeof(version)) != sizeof(version))
		errx(1, "Empty file");

	if (version != GOSSIP_STORE_VERSION)
		warnx("UNSUPPORTED GOSSIP VERSION %u (expected %u)",
		      version, GOSSIP_STORE_VERSION);

	printf("GOSSIP VERSION %u\n", version);
	off = 1;

	while (read(fd, &hdr, sizeof(hdr)) == sizeof(hdr)) {
		struct amount_sat sat;
		u32 msglen = be32_to_cpu(hdr.len);
		u8 *msg, *inner;
		bool deleted = (msglen & GOSSIP_STORE_LEN_DELETED_BIT);

		msglen &= ~GOSSIP_STORE_LEN_DELETED_BIT;
		msg = tal_arr(NULL, u8, msglen);
		if (read(fd, msg, msglen) != msglen)
			errx(1, "%zu: Truncated file?", off);

		if (be32_to_cpu(hdr.crc)
		    != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen))
			warnx("Checksum verification failed");

		if (deleted) {
			printf("%zu: DELETED\n", off);
		} else if (fromwire_gossip_store_channel_amount(msg, &sat)) {
			printf("%zu: channel_amount: %s\n", off,
			       type_to_string(tmpctx, struct amount_sat, &sat));
		} else if (fromwire_peektype(msg) == WIRE_CHANNEL_ANNOUNCEMENT) {
			printf("%zu: t=%u channel_announcement: %s\n",
			       off, be32_to_cpu(hdr.timestamp),
			       tal_hex(msg, msg));
		} else if (fromwire_peektype(msg) == WIRE_CHANNEL_UPDATE) {
			printf("%zu: t=%u channel_update: %s\n",
			       off, be32_to_cpu(hdr.timestamp),
			       tal_hex(msg, msg));
		} else if (fromwire_peektype(msg) == WIRE_NODE_ANNOUNCEMENT) {
			printf("%zu: t=%u node_announcement: %s\n",
			       off, be32_to_cpu(hdr.timestamp),
			       tal_hex(msg, msg));
		} else if (fromwire_peektype(msg) == WIRE_GOSSIPD_LOCAL_ADD_CHANNEL) {
			printf("%zu: local_add_channel: %s\n",
			       off, tal_hex(msg, msg));
		} else if (fromwire_gossip_store_private_update(msg, msg,
								&inner)) {
			printf("%zu: private channel_update: %s\n",
			       off, tal_hex(msg, inner));
		} else {
			warnx("%zu: Unknown message %u",
			      off, fromwire_peektype(msg));
		}
		off += sizeof(hdr) + msglen;
		tal_free(msg);
	}
	return 0;
}
