#include <bitcoin/short_channel_id.h>
#include <ccan/crc/crc.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/amount.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_store.h>
#include <gossipd/gossip_store.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>


struct scidsat {
	struct short_channel_id scid;
        struct amount_sat sat;
} scidsat;

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

        while(fscanf(scidf, "%s ,%ld\n", str, &scidsats[i].sat.satoshis) == 2 ) { /* Raw: read from file */
		if (!short_channel_id_from_str(str, strlen(str), &scidsats[i].scid, 0))
			err(1, "failed to make scid struct");
		i++;
	}
	return scidsats;
}

int main(int argc, char *argv[])
{
	u8 version;
	beint16_t be_inlen;
	struct amount_sat sat;
	bool verbose = false;
	char *infile = NULL, *outfile = NULL, *csvfile = NULL, *csat = NULL;
	int infd, outfd, scidi = 0, channels = 0, nodes = 0, updates = 0;
	struct scidsat *scidsats;
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

	if (outfile) {
		outfd = open(outfile, O_WRONLY|O_TRUNC|O_CREAT, 0666);
		if (outfd < 0)
			err(1, "opening %s", outfile);
	} else
		outfd = STDOUT_FILENO;

	version = GOSSIP_STORE_VERSION;
	if (!write_all(outfd, &version, sizeof(version)))
		err(1, "Writing version");

	while (read_all(infd, &be_inlen, sizeof(be_inlen))) {
		u32 msglen = be16_to_cpu(be_inlen);
		u8 *inmsg = tal_arr(NULL, u8, msglen), *outmsg;
		beint32_t be_outlen;
		beint32_t becsum;

		if (!read_all(infd, inmsg, msglen))
			err(1, "Only read partial message");

		switch (fromwire_peektype(inmsg)) {
		case WIRE_CHANNEL_ANNOUNCEMENT:
			if (csvfile) {
				struct short_channel_id scid;
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
			        if (!short_channel_id_eq(&scid, &scidsats[scidi].scid))
			        	errx(1, "scid of message does not match scid in csv");
				sat = scidsats[scidi].sat;
				scidi++;
			}
			outmsg = towire_gossip_store_channel_announcement(inmsg, inmsg, sat);
			channels += 1;
			break;
		case WIRE_CHANNEL_UPDATE:
			outmsg = towire_gossip_store_channel_update(inmsg, inmsg);
			updates += 1;
			break;
		case WIRE_NODE_ANNOUNCEMENT:
			outmsg = towire_gossip_store_node_announcement(inmsg, inmsg);
			nodes += 1;
			break;
		default:
			warnx("Unknown message %u (%s)", fromwire_peektype(inmsg),
			      wire_type_name(fromwire_peektype(inmsg)));
			tal_free(inmsg);
			continue;
		}
		if (verbose)
			fprintf(stderr, "%s->%s\n",
				wire_type_name(fromwire_peektype(inmsg)),
				gossip_store_type_name(fromwire_peektype(outmsg)));

		becsum = cpu_to_be32(crc32c(0, outmsg, tal_count(outmsg)));
		be_outlen = cpu_to_be32(tal_count(outmsg));
		if (!write_all(outfd, &be_outlen, sizeof(be_outlen))
		    || !write_all(outfd, &becsum, sizeof(becsum))
		    || !write_all(outfd, outmsg, tal_count(outmsg))) {
			exit(1);
		}
		tal_free(inmsg);
		if (--max == 0)
			break;
	}
	fprintf(stderr, "channels %d, updates %d, nodes %d\n", channels, updates, nodes);
	if (csvfile)
                tal_free(scidsats);
	return 0;
}
