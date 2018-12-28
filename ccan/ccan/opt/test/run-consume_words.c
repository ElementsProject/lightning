#include <ccan/tap/tap.h>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>

/* Test consume_words helper. */
int main(void)
{
	size_t prefix, len;
	bool start = true;

	plan_tests(27);

	/* Every line over width. */
	len = consume_words("hello world", 1, &prefix, &start);
	ok1(prefix == 0);
	ok1(!start);
	ok1(len == strlen("hello"));
	len = consume_words(" world", 1, &prefix, &start);
	ok1(prefix == 1);
	ok1(len == strlen("world"));
	ok1(!start);
	ok1(consume_words("", 1, &prefix, &start) == 0);

	/* Same with width where won't both fit. */
	start = true;
	len = consume_words("hello world", 5, &prefix, &start);
	ok1(!start);
	ok1(prefix == 0);
	ok1(len == strlen("hello"));
	len = consume_words(" world", 5, &prefix, &start);
	ok1(!start);
	ok1(prefix == 1);
	ok1(len == strlen("world"));
	ok1(consume_words("", 5, &prefix, &start) == 0);

	start = true;
	len = consume_words("hello world", 11, &prefix, &start);
	ok1(!start);
	ok1(prefix == 0);
	ok1(len == strlen("hello world"));
	ok1(consume_words("", 11, &prefix, &start) == 0);

	/* Now try a literal, should not be broken */
	start = true;
	len = consume_words(" hello world", 5, &prefix, &start);
	ok1(!start);
	ok1(prefix == 1);
	ok1(len == strlen("hello world"));

	/* A literal after an explicit \n also not broken */
	start = true;
	len = consume_words("hi\n hello world", 5, &prefix, &start);
	ok1(start);
	ok1(prefix == 0);
	ok1(len == strlen("hi\n"));
	len = consume_words(" hello world", 5, &prefix, &start);
	ok1(!start);
	ok1(prefix == 1);
	ok1(len == strlen("hello world"));

	return exit_status();
}
