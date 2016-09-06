#include <ccan/crypto/sha256/sha256.h>
#include <ccan/str/hex/hex.h>
/* Include the C files directly. */
#include <ccan/crypto/sha256/sha256.c>
#include <ccan/tap/tap.h>

/* Test vectors. */
struct test {
	const char *test;
	size_t repetitions;
	const char *result;
};

static struct test tests[] = {
	{ "", 1,
	  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
	{ "abc", 1,
	  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
	  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
	  "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
	{ "a", 1000000,
	  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" }
#if 0 /* Good test, but takes ages! */
	, { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
	    16777216,
	    "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e" },
#endif
};

static bool do_test(const struct test *t)
{
	struct sha256 h, expected;

	if (t->repetitions == 1)
		sha256(&h, t->test, strlen(t->test));
	else {
		struct sha256_ctx ctx = SHA256_INIT;
		size_t i;

		for (i = 0; i < t->repetitions; i++)
			sha256_update(&ctx, t->test, strlen(t->test));
		sha256_done(&ctx, &h);
	}

	hex_decode(t->result, strlen(t->result), &expected, sizeof(expected));
	return memcmp(&h, &expected, sizeof(h)) == 0;
}

int main(void)
{
	const size_t num_tests = sizeof(tests) / sizeof(tests[0]);
	size_t i;

	/* This is how many tests you plan to run */
	plan_tests(num_tests);

	for (i = 0; i < num_tests; i++)
		ok1(do_test(&tests[i]));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
