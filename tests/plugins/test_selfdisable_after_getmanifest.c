#include "config.h"
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/json.h>
#include <common/setup.h>
#include <common/utils.h>
#include <unistd.h>

/* Our normal frameworks don't (yet?) support custom post-manifest responses,
 * so this is open-coded */
int main(int argc, char *argv[])
{
	char *buf;
	int r, off;
	const jsmntok_t *toks, *id;

	common_setup(argv[0]);

	buf = tal_arr(tmpctx, char, 100);
	off = 0;
	do {
		r = read(STDIN_FILENO, buf + off, tal_bytelen(buf) - off);
		if (r < 0)
			err(1, "reading stdin");
		off += r;
		if (off == tal_bytelen(buf))
			tal_resize(&buf, off * 2);

		toks = json_parse_simple(tmpctx, buf, off);
	} while (!toks);

	/* Tell it we're disabled (reusing id). */
	id = json_get_member(buf, toks, "id");
	buf = tal_fmt(tmpctx, "{\"jsonrpc\":\"2.0\",\"id\":%.*s,\"result\":{\"disable\":\"Self-disable test after getmanifest\"} }",
		      json_tok_full_len(id),
		      json_tok_full(buf, id));
	write_all(STDOUT_FILENO, buf, strlen(buf));

	common_shutdown();
	return 0;
}
