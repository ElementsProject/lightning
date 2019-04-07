#include <ccan/crc/crc.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
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
#include <wire/gen_peer_wire.h>

int main(int argc, char *argv[])
{
	u8 version;
	beint16_t be_inlen;
	struct amount_sat sat;
	bool verbose = false;
	char *infile = NULL, *outfile = NULL;
	int infd, outfd;

	setup_locale();

	opt_register_noarg("--verbose|-v", opt_set_bool, &verbose,
			   "Print progress to stderr");
	opt_register_arg("--output|-o", opt_set_charp, NULL, &outfile,
			 "Send output to this file instead of stdout");
	opt_register_arg("--input|-i", opt_set_charp, NULL, &infile,
			 "Read input from this file instead of stdin");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "default-satoshis\n"
			   "Create gossip store, from be16 / input messages",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 2)
		errx(1, "Need default-satoshi argument for channel amounts");
	if (!parse_amount_sat(&sat, argv[1], strlen(argv[1])))
		errx(1, "Invalid satoshi amount %s", argv[1]);

	if (infile) {
		infd = open(infile, O_RDONLY);
		if (infd < 0)
			err(1, "opening %s", infile);
	} else
		infd = STDIN_FILENO;

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
			outmsg = towire_gossip_store_channel_announcement(inmsg, inmsg, sat);
			break;
		case WIRE_CHANNEL_UPDATE:
			outmsg = towire_gossip_store_channel_update(inmsg, inmsg);
			break;
		case WIRE_NODE_ANNOUNCEMENT:
			outmsg = towire_gossip_store_node_announcement(inmsg, inmsg);
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
	}
	return 0;
}
