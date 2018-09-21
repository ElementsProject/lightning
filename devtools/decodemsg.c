#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <common/decode_short_channel_ids.h>
#include <common/utils.h>
#include <devtools/gen_print_onion_wire.h>
#include <devtools/gen_print_wire.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const u8 *m;
	bool onion = false;
	setup_locale();

	opt_register_noarg("--onion", opt_set_bool, &onion,
			   "Decode an error message instead of a peer message");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "[<hexmsg>]"
			   "Decode a lightning spec wire message from hex, or a series of messages from stdin",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc > 2)
		opt_usage_and_exit("Too many arguments");

	if (argc == 2) {
		/* Arg is hex string */
		m = tal_hexdata(NULL, argv[1], strlen(argv[1]));
		if (!m)
			errx(1, "'%s' is not valid hex", argv[1]);

		if (onion)
			printonion_type_message(m);
		else
			printwire_type_message(m);
	} else {
		u8 *f = grab_fd(NULL, STDIN_FILENO);
		size_t off = 0;

		while (off != tal_count(f)) {
			be16 len;

			if (off + sizeof(len) > tal_count(f)) {
				warnx("Truncated file");
				break;
			}
			memcpy(&len, f + off, sizeof(len));
			off += sizeof(len);
			if (off + be16_to_cpu(len) > tal_count(f)) {
				warnx("Truncated file");
				break;
			}
			m = tal_dup_arr(f, u8, f + off, be16_to_cpu(len), 0);
			if (onion)
				printonion_type_message(m);
			else
				printwire_type_message(m);
			off += be16_to_cpu(len);
			tal_free(m);
		}
	}
	return 0;
}
