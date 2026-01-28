/*~ This is a cute little standalone program that copies the gossip store, minus
 * any deleted records.  gossipd fires us up to create a compacted gossip store.
 * When we're done, we tell it (via stdout) and it tells us when it's ready to
 * wait for the final part.
 */
#include "config.h"
#include <ccan/crc32c/crc32c.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <common/gossip_store.h>
#include <common/gossip_store_wiregen.h>
#include <common/setup.h>
#include <common/utils.h>
#include <common/version.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

static void writex(int fd, const void *p, size_t len)
{
	if (!write_all(fd, p, len))
		err(1, "Could not write new gossip_store");
}

static size_t readx(int fd, void *p, size_t len)
{
	if (!read_all(fd, p, len))
		err(1, "Could not read old gossip_store");
	return len;
}

static size_t skipx(int fd, size_t len)
{
	if (lseek(fd, len, SEEK_CUR) == (off_t)-1)
		err(1, "Could not seek on old gossip_store");
	return len;
}

static void writerec(int fd, const void *msg)
{
	struct gossip_hdr ghdr;

	ghdr.flags = cpu_to_be16(GOSSIP_STORE_COMPLETED_BIT);
	ghdr.len = cpu_to_be16(tal_bytelen(msg));
	ghdr.timestamp = 0;
	ghdr.crc = cpu_to_be32(crc32c(be32_to_cpu(ghdr.timestamp),
				      msg, tal_bytelen(msg)));
	writex(fd, &ghdr, sizeof(ghdr));
	writex(fd, msg, tal_bytelen(msg));
}

static u64 copy_records(int oldfd, int newfd, u64 old_off, u64 limit,
			bool keep_delete_chan)
{
	u8 buffer[65535];

	while (old_off < limit) {
		size_t reclen;
		struct gossip_hdr_and_type hdr;

		old_off += readx(oldfd, &hdr, GOSSIP_HDR_AND_TYPE_SIZE);

		/* We read 2 bytes already */
		reclen = be16_to_cpu(hdr.hdr.len) - 2;

		/* Skip old uuid and deleted records, */
		if (be16_to_cpu(hdr.type) == WIRE_GOSSIP_STORE_UUID
		    || (be16_to_cpu(hdr.hdr.flags) & GOSSIP_STORE_DELETED_BIT)) {
			old_off += skipx(oldfd, reclen);
			continue;
		}

		/* Are we supposed to skip deleted markers? */
		if (!keep_delete_chan
		    && be16_to_cpu(hdr.type) == WIRE_GOSSIP_STORE_DELETE_CHAN) {
			old_off += skipx(oldfd, reclen);
			continue;
		}

		if (!((be16_to_cpu(hdr.hdr.flags) & GOSSIP_STORE_COMPLETED_BIT)))
			errx(1, "Incomplete gossip_store record at %"PRIu64,
			     old_off - GOSSIP_HDR_AND_TYPE_SIZE);

		old_off += readx(oldfd, buffer, reclen);

		writex(newfd, &hdr, GOSSIP_HDR_AND_TYPE_SIZE);
		writex(newfd, buffer, reclen);
	}

	return old_off;
}

int main(int argc, char *argv[])
{
	int oldfd, newfd;
	u8 gsversion, byte;
	u8 uuid[32];
	u64 old_off, limit;

	common_setup(argv[0]);
	/* Not really a subdaemon (we don't use status_xxx) but we can pretend */
	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	if (argc != 5)
		errx(1, "Usage: %s <oldstore> <newstore> <oldstorelen> <uuid>",
			argv[0]);

	oldfd = open(argv[1], O_RDONLY);
	if (oldfd < 0)
		err(1, "Could not open old gossip_store %s", argv[1]);
	newfd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (newfd < 0)
		err(1, "Could not open new gossip_store %s", argv[2]);
	limit = atol(argv[3]);
	if (!hex_decode(argv[4], strlen(argv[4]), uuid, sizeof(uuid)))
		errx(1, "Invalid uuid %s", argv[1]);

	/* Copy version byte */
	old_off = readx(oldfd, &gsversion, sizeof(gsversion));
	writex(newfd, &gsversion, sizeof(gsversion));

	/* Create uuid hdr. */
	writerec(newfd, towire_gossip_store_uuid(tmpctx, uuid));

	old_off = copy_records(oldfd, newfd, old_off, limit, false);
	/* We should hit limit exactly */
	if (old_off != limit)
		errx(1, "We reached offset %"PRIu64" past initial limit %"PRIu64,
		     old_off, limit);

	/* Now we tell gossipd we're done, and it pauses while we copy the last bit.
	 * Note that we need to keep any "delete_channel" records here, since that
	 * would have happened since we copied the first part, and we might have
	 * missed the deleted bit on those channels. */
	byte = 0;
	writex(STDOUT_FILENO, &byte, sizeof(byte));
	readx(STDIN_FILENO, &byte, sizeof(byte));

	limit = lseek(oldfd, 0, SEEK_END);
	lseek(oldfd, old_off, SEEK_SET);
	old_off = copy_records(oldfd, newfd, old_off, limit, true);

	/* We should hit EOF exactly */
	if (old_off != limit)
		errx(1, "We reached offset %"PRIu64" before file size %"PRIu64,
		     old_off, limit);

	common_shutdown();
}
