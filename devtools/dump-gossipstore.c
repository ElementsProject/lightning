#include <ccan/crc/crc.h>
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
	beint32_t belen, becsum;

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

	while (read(fd, &belen, sizeof(belen)) == sizeof(belen) &&
	       read(fd, &becsum, sizeof(becsum)) == sizeof(becsum)) {
		struct amount_sat sat;
		struct short_channel_id scid;
		u32 msglen = be32_to_cpu(belen);
		u8 *msg = tal_arr(NULL, u8, msglen);

		if (read(fd, msg, msglen) != msglen)
			errx(1, "Truncated file?");

		if (be32_to_cpu(becsum) != crc32c(0, msg, msglen))
			warnx("Checksum verification failed");

		if (fromwire_gossip_store_channel_amount(msg, &sat)) {
			printf("channel_amount: %s\n",
			       type_to_string(tmpctx, struct amount_sat, &sat));
		} else if (fromwire_peektype(msg) == WIRE_CHANNEL_ANNOUNCEMENT) {
			printf("channel_announcement: %s\n", tal_hex(msg, msg));
		} else if (fromwire_peektype(msg) == WIRE_CHANNEL_UPDATE) {
			printf("channel_update: %s\n", tal_hex(msg, msg));
		} else if (fromwire_peektype(msg) == WIRE_NODE_ANNOUNCEMENT) {
			printf("node_announcement: %s\n", tal_hex(msg, msg));
		} else if (fromwire_peektype(msg) == WIRE_GOSSIPD_LOCAL_ADD_CHANNEL) {
			printf("local_add_channel: %s\n", tal_hex(msg, msg));
		} else if (fromwire_gossip_store_channel_delete(msg, &scid)) {
			printf("channel_delete: %s\n",
			       type_to_string(msg, struct short_channel_id,
					      &scid));
		} else {
			warnx("Unknown message %u", fromwire_peektype(msg));
		}
		tal_free(msg);
	}
	return 0;
}
