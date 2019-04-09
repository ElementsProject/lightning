#include <ccan/crc/crc.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <devtools/create-gossipstore.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_store.h>
#include <gossipd/gossip_store.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>



struct scidsat * load_scid_file(FILE * scidfd)
{
        int n, ok;
        ok = fscanf(scidfd, "%d\n", &n);
	if (ok == EOF)
		return NULL;
	char title[16];
        ok = fscanf(scidfd, "%s\n", title);
	if (ok == EOF)
		return NULL;
	struct scidsat * scids = calloc(n, sizeof(scidsat));
	int i = 0;
        while(fscanf(scidfd, "%s ,%" SCNu64 "\n", scids[i].scid, &scids[i].sat.satoshis) == 2 ) { /* Raw: read from file */
			i++;
	}
	return scids;
}

int main(int argc, char *argv[])
{
	u8 version;
	beint16_t be_inlen;
	struct amount_sat sat;
	bool verbose = false;
	char *infile = NULL, *outfile = NULL, *scidfile = NULL, *csat = NULL;
	int infd = 0, outfd;
       	FILE * scidfd;
	struct scidsat * scids = NULL;
	unsigned max = -1U;

	setup_locale();

	opt_register_noarg("--verbose|-v", opt_set_bool, &verbose,
			   "Print progress to stderr");
	opt_register_arg("--output|-o", opt_set_charp, NULL, &outfile,
			 "Send output to this file instead of stdout");
	opt_register_arg("--input|-i", opt_set_charp, NULL, &infile,
			 "Read input from this file instead of stdin");
	opt_register_arg("--scidfile", opt_set_charp, NULL, &scidfile,
			 "Input for 'scid, satshis' csv");
	opt_register_arg("--sat", opt_set_charp, NULL, &csat,
			 "default satoshi value if --scidfile flag not present");
	opt_register_arg("--max", opt_set_uintval, opt_show_uintval, &max,
			 "maximum number of messages to read");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "Create gossip store, from be16 / input messages",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);


        if (scidfile) {
		scidfd = fopen(scidfile, "r");
		if (scidfd < 0)
			err(1, "opening %s", scidfile);
                scids = load_scid_file(scidfd);
	        fclose(scidfd);
	}
	else if (csat) {
		if (!parse_amount_sat(&sat, csat, strlen(csat))) {
		        errx(1, "Invalid satoshi amount %s", csat);
		}
	}
	else {
		err(1, "must contain either --sat xor --scidfile");
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

	int scidi = 0;
	int channels = 0;
	int nodes = 0;
	int updates = 0;
	while (read_all(infd, &be_inlen, sizeof(be_inlen))) {
		u32 msglen = be16_to_cpu(be_inlen);
		u8 *inmsg = tal_arr(NULL, u8, msglen), *outmsg;
		beint32_t be_outlen;
		beint32_t becsum;

		if (!read_all(infd, inmsg, msglen))
			err(1, "Only read partial message");

		switch (fromwire_peektype(inmsg)) {
		case WIRE_CHANNEL_ANNOUNCEMENT:
			if (scids) {
				sat = scids[scidi].sat;
				scidi += 1;
			}
			channels += 1;
			outmsg = towire_gossip_store_channel_announcement(inmsg, inmsg, sat);
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
	free(scids);
	return 0;
}
