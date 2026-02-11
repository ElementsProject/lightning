#include "config.h"
#include <ccan/crc32c/crc32c.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <common/gossip_store.h>
#include <common/setup.h>
#include <common/utils.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wire.h>

/* Current versions we support */
#define GSTORE_MAJOR 0
#define GSTORE_MINOR 16

/* Ended marker for <= 15 */
static bool fromwire_gossip_store_ended_obs(const void *p, u64 *equivalent_offset)
{
	const u8 *cursor = p;
	size_t plen = tal_count(p);

	if (fromwire_u16(&cursor, &plen) != WIRE_GOSSIP_STORE_ENDED)
		return false;
 	*equivalent_offset = fromwire_u64(&cursor, &plen);
	return cursor != NULL;
}


static bool is_channel_announce(const u8 *msg, struct short_channel_id **scid)
{
	secp256k1_ecdsa_signature sig;
	u8 *features;
	struct bitcoin_blkid chain_hash;
	struct node_id node;
	struct pubkey key;

	if (fromwire_peektype(msg) != WIRE_CHANNEL_ANNOUNCEMENT)
		return false;

	*scid = tal(msg, struct short_channel_id);
	if (!fromwire_channel_announcement(msg, msg, &sig, &sig, &sig, &sig, &features,
					   &chain_hash, *scid, &node, &node, &key, &key))
		*scid = tal_free(*scid);
	return true;
}

static bool is_channel_update(const u8 *msg, struct short_channel_id_dir **scidd)
{
	secp256k1_ecdsa_signature sig;
	struct bitcoin_blkid chain_hash;
	u32 u32val;
	u8 message_flags, channel_flags;
	u16 cltv_expiry_delta;
	struct amount_msat msat;

	if (fromwire_peektype(msg) != WIRE_CHANNEL_UPDATE)
		return false;

	*scidd = tal(msg, struct short_channel_id_dir);
	if (fromwire_channel_update(msg, &sig, &chain_hash, &(*scidd)->scid, &u32val, &message_flags, &channel_flags, &cltv_expiry_delta, &msat, &u32val, &u32val, &msat))
		(*scidd)->dir = (channel_flags & ROUTING_FLAGS_DIRECTION);
	else
		*scidd = tal_free(*scidd);
	return true;
}

static bool is_node_announcement(const u8 *msg, struct node_id **node)
{
	secp256k1_ecdsa_signature sig;
	u8 *u8arr;
	u32 timestamp;
	u8 rgb_color[3], alias[32];
	struct tlv_node_ann_tlvs *tlvs;

	if (fromwire_peektype(msg) != WIRE_NODE_ANNOUNCEMENT)
		return false;

	*node = tal(msg, struct node_id);
	if (!fromwire_node_announcement(msg, msg, &sig, &u8arr, &timestamp, *node, rgb_color, alias, &u8arr, &tlvs))
		*node = tal_free(*node);
	return true;
}

int main(int argc, char *argv[])
{
	int fd;
	u8 version;
	struct gossip_hdr hdr;
	size_t off;
	bool print_deleted = false;
	bool print_timestamp = false;

	common_setup(argv[0]);
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
		struct short_channel_id scid, *scidptr;
		struct short_channel_id_dir *sciddptr;
		struct node_id *nodeptr;
		u16 flags = be16_to_cpu(hdr.flags);
		u16 msglen = be16_to_cpu(hdr.len);
		u8 *msg, *inner;
		bool deleted, dying, complete;
		u32 blockheight;
		u64 offset;
		u8 uuid[32];

		deleted = (flags & GOSSIP_STORE_DELETED_BIT);
		dying = (flags & GOSSIP_STORE_DYING_BIT);
		complete = (flags & GOSSIP_STORE_COMPLETED_BIT);

		msg = tal_arr(NULL, u8, msglen);
		if (read(fd, msg, msglen) != msglen)
			errx(1, "%zu: Truncated file?", off);

		printf("%zu: %s%s%s%s", off,
		       deleted ? "DELETED " : "",
		       dying ? "DYING " : "",
		       complete ? "" : "**INCOMPLETE** ",
		       be32_to_cpu(hdr.crc) != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen) ? "**BAD CHECKSUM** " : "");

		if (print_timestamp)
			printf("T=%u ", be32_to_cpu(hdr.timestamp));
		if (deleted && !print_deleted) {
			printf("\n");
			goto end;
		}

		if (fromwire_gossip_store_channel_amount(msg, &sat)) {
			printf("channel_amount: %s\n",
			       fmt_amount_sat(tmpctx, sat));
		} else if (is_channel_announce(msg, &scidptr)) {
			printf("t=%u channel_announcement(%s): %s\n",
			       be32_to_cpu(hdr.timestamp),
			       scidptr ? fmt_short_channel_id(tmpctx, *scidptr) : "?",
			       tal_hex(msg, msg));
		} else if (is_channel_update(msg, &sciddptr)) {
			printf("t=%u channel_update(%s): %s\n",
			       be32_to_cpu(hdr.timestamp),
			       sciddptr ? fmt_short_channel_id_dir(tmpctx, sciddptr) : "?",
			       tal_hex(msg, msg));
		} else if (is_node_announcement(msg, &nodeptr)) {
			printf("t=%u node_announcement(%s): %s\n",
			       be32_to_cpu(hdr.timestamp),
			       nodeptr ? fmt_node_id(tmpctx, nodeptr) : "?",
			       tal_hex(msg, msg));
		} else if (fromwire_gossip_store_private_channel_obs(msg, msg, &sat,
								 &inner)) {
			printf("private channel_announcement: %s %s\n",
			       fmt_amount_sat(tmpctx, sat),
			       tal_hex(msg, inner));
		} else if (fromwire_gossip_store_private_update_obs(msg, msg,
								&inner)) {
			printf("private channel_update: %s\n",
			       tal_hex(msg, inner));
		} else if (fromwire_gossip_store_delete_chan(msg, &scid)) {
			printf("delete channel: %s\n",
			       fmt_short_channel_id(tmpctx, scid));
		} else if (fromwire_gossip_store_chan_dying(msg, &scid, &blockheight)) {
			printf("dying channel: %s (deadline %u)\n",
			       fmt_short_channel_id(tmpctx, scid),
			       blockheight);
		} else if (fromwire_gossip_store_ended(msg, &offset, uuid)) {
			printf("gossip store ended: offset %"PRIu64" in uuid %s\n",
			       offset, tal_hexstr(tmpctx, uuid, sizeof(uuid)));
		} else if (fromwire_gossip_store_ended_obs(msg, &offset)) {
			printf("gossip store ended (v <= 15): offset %"PRIu64"\n",
			       offset);
		} else if (fromwire_gossip_store_uuid(msg, uuid)) {
			printf("uuid %s\n", tal_hexstr(tmpctx, uuid, sizeof(uuid)));
		} else {
			printf("Unknown message %u: %s\n",
			       fromwire_peektype(msg), tal_hex(msg, msg));
		}
	end:
		off += sizeof(hdr) + msglen;
		tal_free(msg);
	}
	common_shutdown();
	return 0;
}
