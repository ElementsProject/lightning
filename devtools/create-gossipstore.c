#include "config.h"
#include <ccan/crc32c/crc32c.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/gossip_store.h>
#include <common/gossip_store_wiregen.h>
#include <common/utils.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wire.h>


struct scidsat {
	struct short_channel_id scid;
        struct amount_sat sat;
};

/* read scid,satoshis csv file and create return an array of scidsat pointers */
static struct scidsat *load_csv_file(FILE *scidf)
{
        int n, r;
	char title[15];
	int i = 0;
	struct scidsat *scidsats;
        /* max characters is 8 (0xffffff) + 8 for tx + 5 (0xffffff) for outputs (0xffff) + 2 (x's) */
        char str[23];

        if (fscanf(scidf, "%d\n", &n) != 1)
                err(1, "reading number of entries from csv failed");

	scidsats = tal_arr(NULL, struct scidsat, n);
        r = fscanf(scidf, "%5s ,%8s\n", title, &title[6]);
	if (r != 2 || strcmp(title, "scid") != 0 || strcmp(&title[6], "satoshis") != 0)
		err(1, "reading 'scid ,satoshis' from csv failed");

        while(fscanf(scidf, "%s ,%"SCNu64"\n", str, &scidsats[i].sat.satoshis) == 2 ) { /* Raw: read from file */
		if (!short_channel_id_from_str(str, strlen(str), &scidsats[i].scid))
			err(1, "failed to make scid struct");
		i++;
	}
	return scidsats;
}

static void write_outmsg(int outfd, const u8 *outmsg, u32 timestamp)
{
	struct gossip_hdr hdr;

	hdr.flags = CPU_TO_BE16(GOSSIP_STORE_COMPLETED_BIT);
	hdr.len = cpu_to_be16(tal_count(outmsg));
	hdr.crc = cpu_to_be32(crc32c(timestamp, outmsg, tal_count(outmsg)));
	hdr.timestamp = cpu_to_be32(timestamp);

	if (!write_all(outfd, &hdr, sizeof(hdr))
	    || !write_all(outfd, outmsg, tal_count(outmsg)))
		err(1, "Writing output");
}

static u32 get_update_timestamp(const u8 *msg, struct short_channel_id *scid)
{
	secp256k1_ecdsa_signature sig;
	struct bitcoin_blkid chain_hash;
	u32 timestamp;
	u8 u8_ignore;
	u16 u16_ignore;
	u32 u32_ignore;
	struct amount_msat msat_ignore;

	if (fromwire_channel_update(msg, &sig, &chain_hash, scid,
				    &timestamp, &u8_ignore, &u8_ignore,
				    &u16_ignore, &msat_ignore, &u32_ignore,
				    &u32_ignore, &msat_ignore))
		return timestamp;
	errx(1, "Invalid channel_update");
}

static u32 get_node_announce_timestamp(const u8 *msg)
{
	secp256k1_ecdsa_signature sig;
	u32 timestamp;
	struct node_id id;
	u8 rgb_color[3], alias[32];
	u8 *features, *addresses;
	struct tlv_node_ann_tlvs *na_tlvs;

	if (fromwire_node_announcement(tmpctx, msg, &sig, &features, &timestamp,
				       &id, rgb_color, alias, &addresses,
				       &na_tlvs))
		return timestamp;

	errx(1, "Invalid node_announcement");
}

int main(int argc, char *argv[])
{
	u8 version;
	beint16_t be_inlen;
	struct amount_sat sat;
	bool verbose = false;
	char *infile = NULL, *outfile = NULL, *csvfile = NULL, *csat = NULL;
	int infd, outfd, scidi = 0, channels = 0, nodes = 0, updates = 0;
	struct scidsat *scidsats = NULL;
	const u8 *last_announce = NULL;
	unsigned max = -1U;

	setup_locale();

	opt_register_noarg("--verbose|-v", opt_set_bool, &verbose,
			   "Print progress to stderr");
	opt_register_arg("--output|-o", opt_set_charp, NULL, &outfile,
			 "Send output to this file instead of stdout");
	opt_register_arg("--input|-i", opt_set_charp, NULL, &infile,
			 "Read input from this file instead of stdin");
	opt_register_arg("--csv", opt_set_charp, NULL, &csvfile,
			 "Input for 'scid, satshis' csv");
	opt_register_arg("--sat", opt_set_charp, NULL, &csat,
			 "default satoshi value if --csv flag not present");
	opt_register_arg("--max", opt_set_uintval, opt_show_uintval, &max,
			 "maximum number of messages to read");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "Create gossip store, from be16 / input messages",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);


        if (csvfile && !csat) {
       	        FILE *scidf;
		scidf = fopen(csvfile, "r");
		if (!scidf)
			err(1, "opening %s", csvfile);
                scidsats = load_csv_file(scidf);
	        fclose(scidf);
	} else if (csat && !csvfile) {
		if (!parse_amount_sat(&sat, csat, strlen(csat))) {
		        errx(1, "Invalid satoshi amount %s", csat);
		}
	}
	else {
		err(1, "must contain either --sat xor --csv");
	}

	if (infile) {
		infd = open(infile, O_RDONLY);
		if (infd < 0)
			err(1, "opening %s", infile);
	}
	else
		infd = STDIN_FILENO;

	if (outfile) {
		outfd = open(outfile, O_WRONLY|O_TRUNC|O_CREAT, 0666);
		if (outfd < 0)
			err(1, "opening %s", outfile);
	} else
		outfd = STDOUT_FILENO;

	version = ((0 << 5) | 10);
	if (!write_all(outfd, &version, sizeof(version)))
		err(1, "Writing version");

	while (read_all(infd, &be_inlen, sizeof(be_inlen))) {
		u32 msglen = be16_to_cpu(be_inlen);
		u8 *inmsg = tal_arr(NULL, u8, msglen);
		u32 timestamp;
		struct short_channel_id scid;
		bool handled = false;

		if (!read_all(infd, inmsg, msglen))
			err(1, "Only read partial message");

		if (verbose)
			fprintf(stderr, "%s\n",
				peer_wire_name(fromwire_peektype(inmsg)));

		switch ((enum peer_wire)fromwire_peektype(inmsg)) {
		case WIRE_CHANNEL_ANNOUNCEMENT:
			if (scidsats) {
				/* We ignore these; we just want scid */
				secp256k1_ecdsa_signature sig;
				u8 *features;
				struct bitcoin_blkid hash;
				struct node_id id;
				struct pubkey pubkey;

				if (!fromwire_channel_announcement(inmsg,
								   inmsg,
								   &sig,
								   &sig,
								   &sig,
								   &sig,
								   &features,
								   &hash,
								   &scid,
								   &id,
								   &id,
								   &pubkey,
								   &pubkey))
					errx(1, "bad channel_announcement");
			        if (!short_channel_id_eq(scid, scidsats[scidi].scid))
					errx(1, "scid of channel_announcement does not match scid in csv");
				if (last_announce)
					errx(1, "Expected update before announce");
				last_announce = inmsg;
				inmsg = NULL;
			}
			handled = true;
			break;
		case WIRE_CHANNEL_UPDATE:
			/* We assume update immediately follows announcement */
			timestamp = get_update_timestamp(inmsg, &scid);
			if (last_announce) {
				if (scidsats && !short_channel_id_eq(scid,
							 scidsats[scidi].scid))
					errx(1, "scid of channel_update does not match scid in csv");

				/* Now we have timestamp, write out announce */
				/* First write announce */
				write_outmsg(outfd, last_announce, timestamp);
				last_announce = tal_free(last_announce);
				channels += 1;
				/* Now write amount */
				write_outmsg(outfd,
					     towire_gossip_store_channel_amount(inmsg,
										scidsats ? scidsats[scidi].sat: sat),
					     0);
				scidi++;
			}
			write_outmsg(outfd, inmsg, timestamp);
			updates += 1;
			handled = true;
			break;
		case WIRE_NODE_ANNOUNCEMENT:
			timestamp = get_node_announce_timestamp(inmsg);
			write_outmsg(outfd, inmsg, timestamp);
			nodes += 1;
			handled = true;
			break;
		case WIRE_WARNING:
		case WIRE_INIT:
		case WIRE_ERROR:
		case WIRE_OPEN_CHANNEL:
		case WIRE_ACCEPT_CHANNEL:
		case WIRE_FUNDING_CREATED:
		case WIRE_FUNDING_SIGNED:
		case WIRE_CHANNEL_READY:
		case WIRE_SHUTDOWN:
		case WIRE_CLOSING_SIGNED:
		case WIRE_CLOSING_COMPLETE:
		case WIRE_CLOSING_SIG:
		case WIRE_UPDATE_ADD_HTLC:
		case WIRE_UPDATE_FULFILL_HTLC:
		case WIRE_UPDATE_FAIL_HTLC:
		case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		case WIRE_PROTOCOL_BATCH_ELEMENT:
		case WIRE_START_BATCH:
		case WIRE_COMMITMENT_SIGNED:
		case WIRE_REVOKE_AND_ACK:
		case WIRE_UPDATE_FEE:
		case WIRE_UPDATE_BLOCKHEIGHT:
		case WIRE_CHANNEL_REESTABLISH:
		case WIRE_ANNOUNCEMENT_SIGNATURES:
		case WIRE_PING:
		case WIRE_PONG:
		case WIRE_QUERY_SHORT_CHANNEL_IDS:
		case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		case WIRE_QUERY_CHANNEL_RANGE:
		case WIRE_REPLY_CHANNEL_RANGE:
		case WIRE_GOSSIP_TIMESTAMP_FILTER:
		case WIRE_ONION_MESSAGE:
		case WIRE_TX_ADD_INPUT:
		case WIRE_TX_REMOVE_INPUT:
		case WIRE_TX_ADD_OUTPUT:
		case WIRE_TX_REMOVE_OUTPUT:
		case WIRE_TX_COMPLETE:
		case WIRE_TX_SIGNATURES:
		case WIRE_TX_INIT_RBF:
		case WIRE_TX_ACK_RBF:
		case WIRE_TX_ABORT:
		case WIRE_PEER_STORAGE:
		case WIRE_PEER_STORAGE_RETRIEVAL:
		case WIRE_OPEN_CHANNEL2:
		case WIRE_ACCEPT_CHANNEL2:
		case WIRE_STFU:
		case WIRE_SPLICE_INIT:
		case WIRE_SPLICE_ACK:
		case WIRE_SPLICE_LOCKED:
			break;
		}
		if (!handled) {
			warnx("Unknown message %u (%s)", fromwire_peektype(inmsg),
			      peer_wire_name(fromwire_peektype(inmsg)));
			tal_free(inmsg);
			continue;
		}
		tal_free(inmsg);
		if (--max == 0)
			break;
	}
	fprintf(stderr, "channels %d, updates %d, nodes %d\n", channels, updates, nodes);
	tal_free(scidsats);
	return 0;
}
