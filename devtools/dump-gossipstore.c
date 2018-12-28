#include <ccan/crc/crc.h>
#include <ccan/err/err.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_store.h>
#include <gossipd/gossip_store.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
		u64 satoshis;
		struct short_channel_id scid;
		u8 *gossip_msg;
		u32 msglen = be32_to_cpu(belen);
		u8 *msg = tal_arr(NULL, u8, msglen);

		if (read(fd, msg, msglen) != msglen)
			errx(1, "Truncated file?");

		if (be32_to_cpu(becsum) != crc32c(0, msg, msglen))
			warnx("Checksum verification failed");

		if (fromwire_gossip_store_channel_announcement(msg, msg,
							       &gossip_msg,
							       &satoshis)) {
			printf("channel_announce for %"PRIu64" satoshis: %s\n",
			       satoshis, tal_hex(msg, gossip_msg));
		} else if (fromwire_gossip_store_channel_update(msg, msg,
								&gossip_msg)) {
			printf("channel_update: %s\n",
			       tal_hex(msg, gossip_msg));
		} else if (fromwire_gossip_store_node_announcement(msg, msg,
								   &gossip_msg)) {
			printf("node_announcement: %s\n",
			       tal_hex(msg, gossip_msg));
		} else if (fromwire_gossip_store_channel_delete(msg, &scid)) {
			printf("channel_delete: %s\n",
			       type_to_string(msg, struct short_channel_id,
					      &scid));
		} else if (fromwire_gossip_store_local_add_channel(
			       msg, msg, &gossip_msg)) {
			printf("local_add_channel: %s\n",
			       tal_hex(msg, gossip_msg));
		} else {
			warnx("Unknown message %u", fromwire_peektype(msg));
		}
		tal_free(msg);
	}
	return 0;
}
