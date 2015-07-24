#include <ccan/crypto/shachain/shachain.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include "bitcoin/tx.h"
#include <unistd.h>

#define OP_PUSHDATA1	0x4C
#define OP_PUSHDATA2	0x4D
#define OP_PUSHDATA4	0x4E

static bool pull_value(const u8 **s, const u8 *end, void *dst, size_t max)
{
	size_t len;

	if (*s >= end)
		return false;

	if (**s < 76) {
		len = **s;
		(*s)++;
	} else if (**s == OP_PUSHDATA1) {
		(*s)++;
		if (*s >= end)
			return false;
		len = **s;
		(*s)++;
	} else if (**s == OP_PUSHDATA2) {
		(*s)++;
		if (*s + 1 >= end)
			return false;
		len = (u32)(*s)[0] | ((u32)(*s)[1] << 8);
		(*s) += 2;
	} else if (**s == OP_PUSHDATA4) {
		(*s)++;
		if (*s + 3 >= end)
			return false;
		len = (u32)(*s)[0] | ((u32)(*s)[1] << 8) | ((u32)(*s)[2] << 16)
			| ((u32)(*s)[3] << 24);
		(*s) += 4;
	} else
		return false;

	if (len > max)
		return false;
	memcpy(dst, *s, len);
	(*s) += len;
	return true;
}

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct bitcoin_tx *tx;
	const u8 *s, *end;
	struct sha256 secret;
	u8 sig[73];
	char hexstr[hex_str_size(sizeof(secret))];

	err_set_progname(argv[0]);

	/* FIXME: Take update.pbs to adjust channel */
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<escape-txfile>\n"
			   "Print the secret revealed by this escape tx",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 2)
		opt_usage_exit_fail("Expected 1 argument");

	tx = bitcoin_tx_from_file(ctx, argv[1]);

	if (tx->input_count != 1)
		errx(1, "Expected 1 input");

	s = tx->input[0].script;
	end = s + tx->input[0].script_length;

	if (!pull_value(&s, end, NULL, 0))
		errx(1, "Expected 0");
	if (!pull_value(&s, end, sig, sizeof(sig)))
		errx(1, "Expected sig1");
	if (!pull_value(&s, end, sig, sizeof(sig)))
		errx(1, "Expected sig2");
	if (!pull_value(&s, end, secret.u.u8, sizeof(secret.u.u8)))
		errx(1, "Expected secret");

	if (!hex_encode(&secret.u.u8, sizeof(secret.u.u8), hexstr, sizeof(hexstr)))
		abort();

	/* Print it out. */
	if (!write_all(STDOUT_FILENO, hexstr, strlen(hexstr)))
		err(1, "Writing out secret");

	tal_free(ctx);
	return 0;
}
