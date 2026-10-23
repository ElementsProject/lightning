/* Regression test (auditor-added, temporary): with SHACHAIN_BITS < 64,
 * following the documented rule "You can only add shachain_next_index(@chain)"
 * past chain exhaustion (index 0) wraps next_index to UINT64_MAX; continuing
 * reaches an index whose count_trailing_zeroes() exceeds SHACHAIN_BITS,
 * and shachain_add_hash writes known[pos] out of bounds.
 *
 * Against current code the canary after struct shachain is clobbered
 * (and ASan reports a stack-buffer-overflow in shachain_add_hash).
 * Must pass once additions beyond the chain domain are rejected.
 */
#define SHACHAIN_BITS 8

#include <ccan/crypto/shachain/shachain.h>
/* Include the C files directly. */
#include <ccan/crypto/shachain/shachain.c>
#include <ccan/tap/tap.h>

#include <string.h>
#include <unistd.h>

#define CANARY 0xDEADBEEFCAFEF00DULL

int main(void)
{
	struct {
		struct shachain chain;
		uint64_t canary;
	} w;
	struct sha256 seed, h;
	struct sha256 expect[256];
	uint64_t i;
	unsigned int n;

	alarm(10);
	plan_tests(4);

	memset(&seed, 0xA5, sizeof(seed));
	for (i = 0; i < 256; i++)
		shachain_from_seed(&seed, i, &expect[i]);

	shachain_init(&w.chain);
	w.canary = CANARY;

	ok1(shachain_next_index(&w.chain) == 255);

	/* Exhaust the chain: 255 down to 0, obeying next_index. */
	for (i = 255, n = 0; ; i--) {
		if (shachain_next_index(&w.chain) != i)
			break;
		shachain_from_seed(&seed, i, &h);
		if (!shachain_add_hash(&w.chain, i, &h))
			break;
		n++;
		if (i == 0)
			break;
	}
	ok1(n == 256);

	/* All values still derivable. */
	for (i = 0, n = 0; i < 256; i++) {
		if (shachain_get_hash(&w.chain, i, &h)
		    && memcmp(&h, &expect[i], sizeof(h)) == 0)
			n++;
	}
	ok1(n == 256);

	/* Keep obeying "add shachain_next_index(@chain)": next_index wrapped
	 * to UINT64_MAX.  At index 0xFFFFFFFFFFFFFE00 (511 steps on),
	 * count_trailing_zeroes(index) == 9 > SHACHAIN_BITS and the
	 * unguarded known[pos] write lands past the array.  A repaired
	 * module rejects the out-of-domain addition instead. */
	for (i = 0; i < 600; i++) {
		uint64_t idx = shachain_next_index(&w.chain);
		shachain_from_seed(&seed, idx, &h);
		if (!shachain_add_hash(&w.chain, idx, &h))
			break;
		if (w.canary != CANARY)
			break;
	}
	ok1(w.canary == CANARY);

	return exit_status();
}
