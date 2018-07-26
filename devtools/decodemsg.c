#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <common/decode_short_channel_ids.h>
#include <common/utils.h>
#include <devtools/gen_print_onion_wire.h>
#include <devtools/gen_print_wire.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	const u8 *m;
	bool onion = false;
	setup_locale();

	opt_register_noarg("--onion", opt_set_bool, &onion,
			   "Decode an error message instead of a peer message");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<hexmsg>"
			   "Decode a lightning spec wire message from hex.",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 2)
		errx(1, "Need a hex message");

	/* Arg is hex string */
	m = tal_hexdata(NULL, argv[1], strlen(argv[1]));
	if (!m)
		errx(1, "'%s' is not valid hex", argv[1]);

	if (onion)
		printonion_type_message(m);
	else
		printwire_type_message(m);
	return 0;
}
