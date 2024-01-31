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

/* Current versions we support */
#define GSTORE_MAJOR 0
#define GSTORE_MINOR 12

int main(int argc, char *argv[])
{
	int fd;
	u8 version;
	struct gossip_hdr hdr;
	size_t off;
	bool print_deleted = false;
	bool print_timestamp = false;

	setup_locale();
	opt_register_noarg("--print-deleted", opt_set_bool, &print_deleted,
			   "Print deleted entries too");
	opt_register_noarg("--print-timestamps", opt_set_bool, &print_timestamp,
			   "Print timestamp with entries");
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

	if (GOSSIP_STORE_MAJOR_VERSION(version) != GSTORE_MAJOR)
		errx(1, "Unsupported major gossip_version %u (expected %u)",
		     GOSSIP_STORE_MAJOR_VERSION(version), GSTORE_MAJOR);

	/* Unsupported minor just means we might not understand all fields,
	 * or all flags. */
	if (GOSSIP_STORE_MINOR_VERSION(version) != GSTORE_MINOR)
		warnx("UNKNOWN GOSSIP minor VERSION %u (expected %u)",
		      GOSSIP_STORE_MINOR_VERSION(version), GSTORE_MINOR);

	printf("GOSSIP VERSION %u/%u\n",
	       GOSSIP_STORE_MINOR_VERSION(version),
	       GOSSIP_STORE_MAJOR_VERSION(version));
	off = 1;

	while (read(fd, &hdr, sizeof(hdr)) == sizeof(hdr)) {
		struct amount_sat sat;
		struct short_channel_id scid;
		u16 flags = be16_to_cpu(hdr.flags);
		u16 msglen = be16_to_cpu(hdr.len);
		u8 *msg, *inner;
		bool deleted, push, ratelimit, zombie, dying;
		u32 blockheight;

		deleted = (flags & GOSSIP_STORE_DELETED_BIT);
		push = (flags & GOSSIP_STORE_PUSH_BIT);
		ratelimit = (flags & GOSSIP_STORE_RATELIMIT_BIT);
		zombie = (flags & GOSSIP_STORE_ZOMBIE_BIT);
		dying = (flags & GOSSIP_STORE_DYING_BIT);

		msg = tal_arr(NULL, u8, msglen);
		if (read(fd, msg, msglen) != msglen)
			errx(1, "%zu: Truncated file?", off);

		if (be32_to_cpu(hdr.crc)
		    != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen))
			warnx("Checksum verification failed");

		printf("%zu: %s%s%s%s%s", off,
		       deleted ? "DELETED " : "",
		       push ? "PUSH " : "",
		       ratelimit ? "RATE-LIMITED " : "",
		       zombie ? "ZOMBIE " : "",
		       dying ? "DYING " : "");
		if (print_timestamp)
			printf("T=%u ", be32_to_cpu(hdr.timestamp));
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
		} else if (fromwire_gossip_store_private_channel_obs(msg, msg, &sat,
								 &inner)) {
			printf("private channel_announcement: %s %s\n",
			       type_to_string(tmpctx, struct amount_sat, &sat),
			       tal_hex(msg, inner));
		} else if (fromwire_gossip_store_private_update_obs(msg, msg,
								&inner)) {
			printf("private channel_update: %s\n",
			       tal_hex(msg, inner));
		} else if (fromwire_gossip_store_delete_chan(msg, &scid)) {
			printf("delete channel: %s\n",
			       type_to_string(tmpctx, struct short_channel_id,
					      &scid));
		} else if (fromwire_gossip_store_chan_dying(msg, &scid, &blockheight)) {
			printf("dying channel: %s (deadline %u)\n",
			       type_to_string(tmpctx, struct short_channel_id,
					      &scid),
			       blockheight);
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
