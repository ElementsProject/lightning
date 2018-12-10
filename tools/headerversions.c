/* Updates the given file if any library versions have changed.  This
 * is important for systemwide updates, such as sqlite3. */
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <fcntl.h>
#include <gmp.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <zlib.h>

int main(int argc, char *argv[])
{
	char *file, *new;

	err_set_progname(argv[0]);

	if (argc != 2)
		errx(1, "Usage: %s <versionheader>", argv[0]);

	file = grab_file(NULL, argv[1]);
	if (!file && errno != ENOENT)
		err(1, "Reading %s", argv[1]);

	new = tal_fmt(NULL,
		      "/* Generated file by tools/headerversions, do not edit! */\n"
		      "/* GMP version: %s */\n"
		      "/* SQLITE3 version: %u */\n"
		      "/* ZLIB version: %s */\n",
		      gmp_version,
		      sqlite3_libversion_number(),
		      zlibVersion());
	if (!file || !streq(new, file)) {
		int fd = open(argv[1], O_TRUNC|O_WRONLY|O_CREAT, 0666);
		if (fd < 0)
			err(1, "Writing %s", argv[1]);
		if (!write_all(fd, new, strlen(new)))
			err(1, "Writing to %s", argv[1]);
		close(fd);
	}
	tal_free(new);
	tal_free(file);
	return 0;
}
