#include <ccan/crypto/ripemd160/ripemd160.h>
/* Include the C files directly. */
#include <ccan/crypto/ripemd160/ripemd160.c>
#include <ccan/tap/tap.h>

/* Test vectors. */
struct test {
	const char *test;
	size_t repetitions;
	beint32_t result[5];
};

/* Test vectors from: http://homes.esat.kuleuven.be/~bosselae/ripemd160.html */
static struct test tests[] = {
	{ "", 1,
	  { CPU_TO_BE32(0x9c1185a5), CPU_TO_BE32(0xc5e9fc54),
	    CPU_TO_BE32(0x61280897), CPU_TO_BE32(0x7ee8f548),
	    CPU_TO_BE32(0xb2258d31) } },
	{ "abc", 1,
	  { CPU_TO_BE32(0x8eb208f7), CPU_TO_BE32(0xe05d987a),
	    CPU_TO_BE32(0x9b044a8e), CPU_TO_BE32(0x98c6b087),
	    CPU_TO_BE32(0xf15a0bfc) } },
	{ "message digest", 1,
	  { CPU_TO_BE32(0x5d0689ef), CPU_TO_BE32(0x49d2fae5),
	    CPU_TO_BE32(0x72b881b1), CPU_TO_BE32(0x23a85ffa),
	    CPU_TO_BE32(0x21595f36) } },
	{ "abcdefghijklmnopqrstuvwxyz", 1,
	  { CPU_TO_BE32(0xf71c2710), CPU_TO_BE32(0x9c692c1b),
	    CPU_TO_BE32(0x56bbdceb), CPU_TO_BE32(0x5b9d2865),
	    CPU_TO_BE32(0xb3708dbc) } },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
	  { CPU_TO_BE32(0x12a05338), CPU_TO_BE32(0x4a9c0c88),
	    CPU_TO_BE32(0xe405a06c), CPU_TO_BE32(0x27dcf49a),
	    CPU_TO_BE32(0xda62eb2b) } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
	  { CPU_TO_BE32(0xb0e20b6e), CPU_TO_BE32(0x31166402),
	    CPU_TO_BE32(0x86ed3a87), CPU_TO_BE32(0xa5713079),
	    CPU_TO_BE32(0xb21f5189) } },
	{ "1234567890", 8,
	  { CPU_TO_BE32(0x9b752e45), CPU_TO_BE32(0x573d4b39),
	    CPU_TO_BE32(0xf4dbd332), CPU_TO_BE32(0x3cab82bf),
	    CPU_TO_BE32(0x63326bfb) } },
	{ "a", 1000000,
	  { CPU_TO_BE32(0x52783243), CPU_TO_BE32(0xc1697bdb),
	    CPU_TO_BE32(0xe16d37f9), CPU_TO_BE32(0x7f68f083),
	    CPU_TO_BE32(0x25dc1528) } }
};

static bool do_test(const struct test *t, bool single)
{
	struct ripemd160 h;

	if (single) {
		if (t->repetitions != 1)
			return true;
		ripemd160(&h, t->test, strlen(t->test));
	} else {
		struct ripemd160_ctx ctx = RIPEMD160_INIT;
		size_t i;

		for (i = 0; i < t->repetitions; i++)
			ripemd160_update(&ctx, t->test, strlen(t->test));
		ripemd160_done(&ctx, &h);
	}

	return memcmp(&h.u, t->result, sizeof(t->result)) == 0;
}

int main(void)
{
	size_t i;

	/* This is how many tests you plan to run */
	plan_tests(sizeof(tests) / sizeof(struct test) * 2);

	for (i = 0; i < sizeof(tests) / sizeof(struct test); i++)
		ok1(do_test(&tests[i], false));

	for (i = 0; i < sizeof(tests) / sizeof(struct test); i++)
		ok1(do_test(&tests[i], true));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
