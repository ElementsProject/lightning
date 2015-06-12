/* Insecure hack to leak signatures early, to make up for non-normalized txs */
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "pkt.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenAnchorScriptsigs *s;
	struct pkt *pkt;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-anchor-sig-file>\n"
			   "Create LeakAnchorSigsAndPretendWeDidnt to stdout",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 2)
		opt_usage_exit_fail("Expected 1 argument");

	s = pkt_from_file(argv[1], PKT__PKT_OPEN_ANCHOR_SCRIPTSIGS)
		->open_anchor_scriptsigs;

	pkt = leak_anchor_sigs_and_pretend_we_didnt_pkt(ctx, s);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
	
