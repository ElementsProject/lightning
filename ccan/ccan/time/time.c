/* Licensed under BSD-MIT - see LICENSE file for details */
#include <ccan/time/time.h>
#include <stdlib.h>
#include <stdio.h>

#if !HAVE_CLOCK_GETTIME
#include <sys/time.h>

struct timeabs time_now(void)
{
	struct timeval now;
	struct timeabs ret;
	gettimeofday(&now, NULL);
	ret.ts.tv_sec = now.tv_sec;
	ret.ts.tv_nsec = now.tv_usec * 1000;
	return TIMEABS_CHECK(ret);
}
#else
#include <time.h>
struct timeabs time_now(void)
{
	struct timeabs ret;
	clock_gettime(CLOCK_REALTIME, &ret.ts);
	return TIMEABS_CHECK(ret);
}
#endif /* HAVE_CLOCK_GETTIME */

struct timemono time_mono(void)
{
	struct timemono ret;
#if TIME_HAVE_MONOTONIC
	clock_gettime(CLOCK_MONOTONIC, &ret.ts);
#else /* Best we can do */
	ret.ts = time_now().ts;
#endif /* !HAVE_TIME_MONOTONIC */
	return TIMEMONO_CHECK(ret);
}

struct timerel time_divide(struct timerel t, unsigned long div)
{
	struct timerel res;
	uint64_t rem, ns;

	/* Dividing seconds is simple. */
	res.ts.tv_sec = TIMEREL_CHECK(t).ts.tv_sec / div;
	rem = t.ts.tv_sec % div;

	/* If we can't fit remainder * 1,000,000,000 in 64 bits? */
#if 0 /* ilog is great, but we use fp for multiply anyway. */
	bits = ilog64(rem);
	if (bits + 30 >= 64) {
		/* Reduce accuracy slightly */
		rem >>= (bits - (64 - 30));
		div >>= (bits - (64 - 30));
	}
#endif
	if (rem & ~(((uint64_t)1 << 30) - 1)) {
		/* FIXME: fp is cheating! */
		double nsec = rem * 1000000000.0 + t.ts.tv_nsec;
		res.ts.tv_nsec = nsec / div;
	} else {
		ns = rem * 1000000000 + t.ts.tv_nsec;
		res.ts.tv_nsec = ns / div;
	}
	return TIMEREL_CHECK(res);
}

struct timerel time_multiply(struct timerel t, unsigned long mult)
{
	struct timerel res;

	/* Are we going to overflow if we multiply nsec? */
	if (mult & ~((1UL << 30) - 1)) {
		/* FIXME: fp is cheating! */
		double nsec = (double)t.ts.tv_nsec * mult;

		res.ts.tv_sec = nsec / 1000000000.0;
		res.ts.tv_nsec = nsec - (res.ts.tv_sec * 1000000000.0);
	} else {
		uint64_t nsec = t.ts.tv_nsec * mult;

		res.ts.tv_nsec = nsec % 1000000000;
		res.ts.tv_sec = nsec / 1000000000;
	}
	res.ts.tv_sec += TIMEREL_CHECK(t).ts.tv_sec * mult;
	return TIMEREL_CHECK(res);
}

struct timespec time_check_(struct timespec t, const char *abortstr)
{
	if (t.tv_sec < 0 || t.tv_nsec >= 1000000000) {
		if (abortstr) {
			fprintf(stderr, "%s: malformed time %li.%09li\n",
				abortstr,
				(long)t.tv_sec, (long)t.tv_nsec);
			abort();
		} else {
			struct timespec old = t;

			if (t.tv_nsec >= 1000000000) {
				t.tv_sec += t.tv_nsec / 1000000000;
				t.tv_nsec %= 1000000000;
			}
			if (t.tv_sec < 0)
				t.tv_sec = 0;

			fprintf(stderr, "WARNING: malformed time"
				" %li seconds %li ns converted to %li.%09li.\n",
				(long)old.tv_sec, (long)old.tv_nsec,
				(long)t.tv_sec, (long)t.tv_nsec);
		}
	}
	return t;
}

struct timerel timerel_check(struct timerel t, const char *abortstr)
{
	struct timerel ret;

	ret.ts = time_check_(t.ts, abortstr);
	return ret;
}

struct timeabs timeabs_check(struct timeabs t, const char *abortstr)
{
	struct timeabs ret;

	ret.ts = time_check_(t.ts, abortstr);
	return ret;
}

struct timemono timemono_check(struct timemono t, const char *abortstr)
{
	struct timemono ret;

	ret.ts = time_check_(t.ts, abortstr);
	return ret;
}
