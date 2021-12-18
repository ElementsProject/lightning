#include "config.h"
#include <ccan/crc32c/crc32c.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <common/gossip_store.h>
#include <common/type_to_string.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wire.h>

int main(int argc, char *argv[])
{
	int fd;
	u8 version;
	struct gossip_hdr hdr;
	size_t off;
	bool print_deleted = false;

	setup_locale();
	opt_register_noarg("--print-deleted", opt_set_bool, &print_deleted,
			   "Print deleted entries too");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "[<gossip_store>]"
			   "Dump all gossip messages in the store",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc > 2)
		opt_usage_and_exit("Too many arguments");

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
		struct short_channel_id scid;
		u32 msglen = be32_to_cpu(hdr.len);
		u8 *msg, *inner;
		bool deleted, push;

		deleted = (msglen & GOSSIP_STORE_LEN_DELETED_BIT);
		push = (msglen & GOSSIP_STORE_LEN_PUSH_BIT);

		msglen &= GOSSIP_STORE_LEN_MASK;
		msg = tal_arr(NULL, u8, msglen);
		if (read(fd, msg, msglen) != msglen)
			errx(1, "%zu: Truncated file?", off);

		if (be32_to_cpu(hdr.crc)
		    != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen))
			warnx("Checksum verification failed");

		printf("%zu: %s%s", off,
		       deleted ? "DELETED " : "",
		       push ? "PUSH " : "");
		if (deleted && !print_deleted) {
			printf("\n");
			goto end;
		}

		if (fromwire_gossip_store_channel_amount(msg, &sat)) {
			printf("channel_amount: %s\n",
			       type_to_string(tmpctx, struct amount_sat, &sat));
		} else if (fromwire_peektype(msg) == WIRE_CHANNEL_ANNOUNCEMENT) {
			printf("t=%u channel_announcement: %s\n",
			       be32_to_cpu(hdr.timestamp),
			       tal_hex(msg, msg));
		} else if (fromwire_peektype(msg) == WIRE_CHANNEL_UPDATE) {
			printf("t=%u channel_update: %s\n",
			       be32_to_cpu(hdr.timestamp),
			       tal_hex(msg, msg));
		} else if (fromwire_peektype(msg) == WIRE_NODE_ANNOUNCEMENT) {
			printf("t=%u node_announcement: %s\n",
			       be32_to_cpu(hdr.timestamp),
			       tal_hex(msg, msg));
		} else if (fromwire_gossip_store_private_channel(msg, msg, &sat,
								 &inner)) {
			printf("private channel_announcement: %s %s\n",
			       type_to_string(tmpctx, struct amount_sat, &sat),
			       tal_hex(msg, inner));
		} else if (fromwire_gossip_store_private_update(msg, msg,
								&inner)) {
			printf("private channel_update: %s\n",
			       tal_hex(msg, inner));
		} else if (fromwire_gossip_store_delete_chan(msg, &scid)) {
			printf("delete channel: %s\n",
			       type_to_string(tmpctx, struct short_channel_id,
					      &scid));
		} else {
			warnx("Unknown message %u",
			      fromwire_peektype(msg));
		}
	end:
		off += sizeof(hdr) + msglen;
		tal_free(msg);
	}
	return 0;
}
