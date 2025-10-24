/* This is test for grab_file_str() and grab_file_raw() functions
 */
#include <ccan/tal/grab_file/grab_file.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <sys/stat.h>
#include <ccan/tal/grab_file/grab_file.c>
#include <ccan/tap/tap.h>
#include <ccan/tal/str/str.h>

int
main(void)
{
	unsigned int	i;
	char 		**split, *str, *raw;
	int 		length;
	struct 		stat st;

	plan_tests(5);
	str = grab_file_str(NULL, "test/run-grab.c");
	split = tal_strsplit(str, str, "\n", STR_EMPTY_OK);
	length = strlen(split[0]);
	ok1(!strcmp(split[0], "This is test for grab_file_str() and grab_file_raw() functions"));
	for (i = 1; split[i]; i++)
		length += strlen(split[i]);
	ok1(!strcmp(split[i-1], "/* End of grab_file.c test */"));
	if (stat("test/run-grab.c", &st) != 0)
		/* FIXME: ditto */
		if (stat("ccan/tal/grab_file/test/run-grab.c", &st) != 0)
			err(1, "Could not stat self");
	ok1(st.st_size == length + i);

	/* Raw does not nul term */
	raw = grab_file_raw(str, "test/run-grab.c");
	ok1(tal_count(raw) + 1 == tal_count(str));
	ok1(memcmp(raw, str, tal_bytelen(raw)) == 0);
	tal_free(str);

	return 0;
}

/* End of grab_file.c test */
