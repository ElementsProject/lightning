#include <ccan/crypto/sha256/sha256.h>
/* Include the C files directly. */
#include <ccan/crypto/sha256/sha256.c>
#include <ccan/tap/tap.h>

/* Test vectors. */
struct test {
	const char *test;
	size_t repetitions;
	beint32_t result[8];
};

static struct test tests[] = {
	{ "", 1,
	  { CPU_TO_BE32(0xe3b0c442), CPU_TO_BE32(0x98fc1c14),
	    CPU_TO_BE32(0x9afbf4c8), CPU_TO_BE32(0x996fb924),
	    CPU_TO_BE32(0x27ae41e4), CPU_TO_BE32(0x649b934c),
	    CPU_TO_BE32(0xa495991b), CPU_TO_BE32(0x7852b855) } },
	{ "abc", 1,
	  { CPU_TO_BE32(0xba7816bf), CPU_TO_BE32(0x8f01cfea),
	    CPU_TO_BE32(0x414140de), CPU_TO_BE32(0x5dae2223),
	    CPU_TO_BE32(0xb00361a3), CPU_TO_BE32(0x96177a9c),
	    CPU_TO_BE32(0xb410ff61), CPU_TO_BE32(0xf20015ad) } },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
	  { CPU_TO_BE32(0x248d6a61), CPU_TO_BE32(0xd20638b8),
	    CPU_TO_BE32(0xe5c02693), CPU_TO_BE32(0x0c3e6039),
	    CPU_TO_BE32(0xa33ce459), CPU_TO_BE32(0x64ff2167),
	    CPU_TO_BE32(0xf6ecedd4), CPU_TO_BE32(0x19db06c1) } },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
	  { CPU_TO_BE32(0xcf5b16a7), CPU_TO_BE32(0x78af8380),
	    CPU_TO_BE32(0x036ce59e), CPU_TO_BE32(0x7b049237),
	    CPU_TO_BE32(0x0b249b11), CPU_TO_BE32(0xe8f07a51),
	    CPU_TO_BE32(0xafac4503), CPU_TO_BE32(0x7afee9d1) } },
	{ "a", 1000000,
	  { CPU_TO_BE32(0xcdc76e5c), CPU_TO_BE32(0x9914fb92),
	    CPU_TO_BE32(0x81a1c7e2), CPU_TO_BE32(0x84d73e67),
	    CPU_TO_BE32(0xf1809a48), CPU_TO_BE32(0xa497200e),
	    CPU_TO_BE32(0x046d39cc), CPU_TO_BE32(0xc7112cd0) } }
#if 0 /* Good test, but takes ages! */
	, { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216,
	    { CPU_TO_BE32(0x50e72a0e), CPU_TO_BE32(0x26442fe2),
	      CPU_TO_BE32(0x552dc393), CPU_TO_BE32(0x8ac58658),
	      CPU_TO_BE32(0x228c0cbf), CPU_TO_BE32(0xb1d2ca87),
	      CPU_TO_BE32(0x2ae43526), CPU_TO_BE32(0x6fcd055e) } }
#endif
};

static bool do_test(const struct test *t, bool single)
{
	struct sha256 h;

	if (single) {
		if (t->repetitions != 1)
			return true;
		sha256(&h, t->test, strlen(t->test));
	} else {
		struct sha256_ctx ctx = SHA256_INIT;
		size_t i;

		for (i = 0; i < t->repetitions; i++)
			sha256_update(&ctx, t->test, strlen(t->test));
		sha256_done(&ctx, &h);
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
