#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	struct sha256 seed, secret;
	bool do_hash = false;
	char hexstr[hex_str_size(sizeof(secret))];

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <index>\n"
			   "A test program to output secret or hash to stdout.",
			   "Print this message.");
	opt_register_noarg("--hash", opt_set_bool, &do_hash,
			   "Output hash instead of secret itself");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 3)
		opt_usage_exit_fail("Expected 2 arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	/* Get the given revoction secret. */
	shachain_from_seed(&seed, atoi(argv[2]), &secret);
	if (do_hash)
		sha256(&secret, secret.u.u8, sizeof(secret.u.u8));

	if (!hex_encode(&secret, sizeof(secret), hexstr, sizeof(hexstr)))
		abort();

	if (!write_all(STDOUT_FILENO, hexstr, strlen(hexstr)))
		err(1, "Writing out hexstr");

	return 0;
}
