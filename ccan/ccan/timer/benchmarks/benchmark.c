#include <ccan/time/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef FIRST_APPROX
#include "first-approx.c"
#endif
#ifdef SECOND_APPROX
#include "second-approx.c"
#endif
#ifdef NO_APPROX
#include "no-approx.c"
#endif

int main(int argc, char *argv[])
{
	struct timespec start, val, val2, end, diff;
	unsigned int i, j, limit = atoi(argv[1] ?: "100000");
	uint64_t val64;

	val = start = time_now();
	val64 = to_u64(start);
	val2.tv_sec = 0;
	val2.tv_nsec = 1;

	for (j = 0; j < limit; j++) {
		for (i = 0; i < limit; i++) {
			val = time_add(val, val2);
			val64 += to_u64(val2);
		}
	}

	end = time_now();

	printf("val64 says %lu.%09lu\n",
	       from_u64(val64).tv_sec,
	       from_u64(val64).tv_nsec);

	printf("val says %lu.%09lu\n",
	       val.tv_sec,
	       val.tv_nsec);

	if (time_greater(val, from_u64(val64)))
		diff = time_sub(val, from_u64(val64));
	else
		diff = time_sub(from_u64(val64), val);

	printf("Time %lluns, error = %i%%\n",
	       (long long)time_to_nsec(time_sub(end, start)),
	       (int)(100 * time_to_nsec(diff) / time_to_nsec(time_sub(val, start))));
	return 0;
}
