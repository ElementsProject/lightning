/* Updates the given file if any library versions have changed.  This
 * is important for systemwide updates, such as sqlite3. */
#include "config.h"
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <fcntl.h>
#include <gmp.h>
#if HAVE_SQLITE3
# include <sqlite3.h>
# define IF_SQLITE3(...) __VA_ARGS__
#else
# define IF_SQLITE3(...)
#endif
#include <unistd.h>
#include <zlib.h>

static const char template[] =
	"/* Generated file by tools/headerversions, do not edit! */\n"
	"/* GMP version: %s */\n"
	IF_SQLITE3("/* SQLITE3 version: %u */\n")
	"/* ZLIB version: %s */\n"
	"#include <ccan/err/err.h>\n"
	"#include <gmp.h>\n"
	IF_SQLITE3("#include <sqlite3.h>\n")
	"#include <zlib.h>\n"
	"\n"
	"static inline void check_linked_library_versions(void)\n"
	"{\n"
	"	char compiled_gmp_version[100];\n"
	IF_SQLITE3(
	"       /* Require at least the version we compiled with. */"
	"	if (SQLITE_VERSION_NUMBER > sqlite3_libversion_number())\n"
	"		errx(1, \"SQLITE version mismatch: compiled %%u, now %%u\",\n"
	"		     SQLITE_VERSION_NUMBER, sqlite3_libversion_number());\n"
	"       /* Ensure the major version matches. */"
	"	if (SQLITE_VERSION_NUMBER + 1000000 < sqlite3_libversion_number())\n"
	"		errx(1, \"SQLITE major version mismatch: compiled %%u, now %%u\",\n"
	"		     SQLITE_VERSION_NUMBER, sqlite3_libversion_number());\n"
	)
	"	/* zlib documents that first char alters ABI. Kudos! */\n"
	"	if (zlibVersion()[0] != ZLIB_VERSION[0])\n"
	"		errx(1, \"zlib version mismatch: compiled %%s, now %%s\",\n"
	"		     ZLIB_VERSION, zlibVersion());\n"
	"	/* GMP doesn't say anything, and we have to assemble our own string. */\n"
	"	snprintf(compiled_gmp_version,  sizeof(compiled_gmp_version),\n"
	"		 \"%%u.%%u.%%u\",\n"
	"		 __GNU_MP_VERSION,\n"
	"		 __GNU_MP_VERSION_MINOR,\n"
	"		 __GNU_MP_VERSION_PATCHLEVEL);\n"
	"	if (strcmp(compiled_gmp_version, gmp_version) != 0)\n"
	"		errx(1, \"gmp version mismatch: compiled %%s, now %%s\",\n"
	"		     compiled_gmp_version, gmp_version);\n"
	"}\n";

int main(int argc, char *argv[])
{
	char *file, *new;

	/* We don't bother with setup_locale(); we're a build tool */
	err_set_progname(argv[0]);

	if (argc != 2)
		errx(1, "Usage: %s <versionheader>", argv[0]);

	file = grab_file(NULL, argv[1]);
	if (!file && errno != ENOENT)
		err(1, "Reading %s", argv[1]);

	new = tal_fmt(NULL, template,
		      gmp_version,
		      IF_SQLITE3(sqlite3_libversion_number(),)
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
