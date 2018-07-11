#include <ccan/err/err.h>
#include <common/decode_short_channel_ids.h>
#include <common/utils.h>
#include <devtools/gen_print_wire.h>
#include <stdio.h>

static void usage(void)
{
	fprintf(stderr, "Usage: decodemsg <msg-in-hex>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	const u8 *m;
	setup_locale();

	if (argc != 2)
		usage();

	/* Last arg is hex string */
	m = tal_hexdata(NULL, argv[1], strlen(argv[1]));
	if (!m)
		errx(1, "'%s' is not valid hex", argv[1]);

	print_message(m);
	return 0;
}
