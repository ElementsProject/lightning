#include <ccan/strmap/strmap.h>
#include <ccan/tal/str/str.h>
#include <common/dissector.h>
#include <common/status.h>
#include <common/utils.h>
#include <ftw.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static char *keys_directory_path = "dissector-keys";

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	int rv = remove(fpath);
	if (rv)
		status_debug("Unable to remove file in dissector-keys %s", fpath);
	return rv;
}

void dissector_init(void)
{
	struct stat st = {0};
	if (stat(keys_directory_path, &st) != -1) {
		if (nftw(keys_directory_path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS) == -1)
			status_debug("Error removing %s", keys_directory_path);
	}
	if (mkdir(keys_directory_path, 0744) != 0) {
		status_debug("Unable to create directory %s", keys_directory_path);
	}
}
 /* Print starting crypto state keys for a connection to file */
void dissector_print_keys(const char *our_addr, const char *peer_addr, const struct crypto_state *cs)
{
	FILE *fp;
	char *filename = tal_fmt(NULL, "%s/%s-%s",
			keys_directory_path, our_addr, peer_addr);

	fp = fopen(filename, "w");
	if (fp == NULL)
		return;

	char *keys = tal_fmt(NULL, "sk:%s\ns_ck:%s\nrk:%s\nr_ck:%s\n",
		tal_hexstr(NULL, &cs->sk, sizeof(cs->sk)),
		tal_hexstr(NULL, &cs->s_ck, sizeof(cs->s_ck)),
		tal_hexstr(NULL, &cs->rk, sizeof(cs->rk)),
		tal_hexstr(NULL, &cs->r_ck, sizeof(cs->r_ck)));

	if (fputs(keys, fp) == -1) {
		status_debug("Error printing keys to %s , exiting early", filename);
		return;
	}

	fclose(fp);
}

void dissector_remove_connection(const char *our_addr, const char *peer_addr)
{
	char *filename = tal_fmt(NULL, "%s/%s-%s",
			keys_directory_path, our_addr, peer_addr);
	if (remove(filename))
		status_debug("Unable to delete %s", filename);

}

