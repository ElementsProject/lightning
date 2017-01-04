/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef CCAN_TIME_H
#define CCAN_TIME_H
#include "config.h"
#include <sys/time.h>
#if HAVE_STRUCT_TIMESPEC
#include <time.h>
#else
struct timespec {
	time_t   tv_sec;        /* seconds */
	long     tv_nsec;       /* nanoseconds */
};
#endif
#include <stdint.h>
#include <stdbool.h>

#ifdef DEBUG
#include <ccan/str/str.h>
#define TIME_CHECK(t) \
	time_check_((t), __FILE__ ":" stringify(__LINE__) " (" stringify(t) ") ")
#define TIMEREL_CHECK(t) \
	timerel_check((t), __FILE__ ":" stringify(__LINE__) " (" stringify(t) ") ")
#define TIMEABS_CHECK(t) \
	timeabs_check((t), __FILE__ ":" stringify(__LINE__) " (" stringify(t) ") ")
#define TIMEMONO_CHECK(t) \
	timemono_check((t), __FILE__ ":" stringify(__LINE__) " (" stringify(t) ") ")
#else
#define TIME_CHECK(t) (t)
#define TIMEREL_CHECK(t) (t)
#define TIMEABS_CHECK(t) (t)
#define TIMEMONO_CHECK(t) (t)
#endif

/**
 * struct timerel - a relative time.
 * @ts: the actual timespec value.
 *
 * For example, 1 second: ts.tv_sec = 1, ts.tv_nsec = 0
 */
struct timerel {
	struct timespec ts;
};

/**
 * struct timeabs - an absolue time.
 * @ts: the actual timespec value.
 *
 * For example, Midnight UTC January 1st, 1970: ts.tv_sec = 0, ts.tv_nsec = 0
 */
struct timeabs {
	struct timespec ts;
};

/**
 * struct timemono - a monotonic time.
 * @ts: the actual timespec value.
 *
 * This comes from the monotonic clock (if available), so it's useful
 * for measuring intervals as it won't change even if the system clock
 * is moved for some reason.
 */
struct timemono {
	struct timespec ts;
};

/**
 * TIME_HAVE_MONOTONIC - defined if we really have a monotonic clock.
 *
 * Otherwise time_mono() just refers to time_now().  Your code might
 * test this if you really need a monotonic clock.
 */
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
#define TIME_HAVE_MONOTONIC 1
#else
#define TIME_HAVE_MONOTONIC 0
#endif

struct timespec time_check_(struct timespec in, const char *abortstr);

/**
 * timerel_check - check if a relative time is malformed.
 * @in: the relative time to check (returned)
 * @abortstr: the string to print to stderr before aborting (if set).
 *
 * This can be used to make sure a time isn't negative and doesn't
 * have a tv_nsec >= 1000000000.  If it is, and @abortstr is non-NULL,
 * that will be printed and abort() is called.  Otherwise, if
 * @abortstr is NULL then the returned timerel will be normalized and
 * tv_sec set to 0 if it was negative.
 *
 * Note that if ccan/time is compiled with DEBUG, then it will call this
 * for all passed and returned times.
 *
 * Example:
 *	printf("Time to calc this was %lu nanoseconds\n",
 *		(long)timerel_check(time_between(time_now(), time_now()),
 *				    "time_now() failed?").ts.tv_nsec);
 */
struct timerel timerel_check(struct timerel in, const char *abortstr);

/**
 * timeabs_check - check if an absolute time is malformed.
 * @in: the absolute time to check (returned)
 * @abortstr: the string to print to stderr before aborting (if set).
 *
 * This can be used to make sure a time isn't negative and doesn't
 * have a tv_nsec >= 1000000000.  If it is, and @abortstr is non-NULL,
 * that will be printed and abort() is called.  Otherwise, if
 * @abortstr is NULL then the returned timeabs will be normalized and
 * tv_sec set to 0 if it was negative.
 *
 * Note that if ccan/time is compiled with DEBUG, then it will call this
 * for all passed and returned times.
 *
 * Example:
 *	printf("Now is %lu seconds since epoch\n",
 *		(long)timeabs_check(time_now(), "time_now failed?").ts.tv_sec);
 */
struct timeabs timeabs_check(struct timeabs in, const char *abortstr);

/**
 * timemono_check - check if a monotonic time is malformed.
 * @in: the monotonic time to check (returned)
 * @abortstr: the string to print to stderr before aborting (if set).
 *
 * This can be used to make sure a time isn't negative and doesn't
 * have a tv_nsec >= 1000000000.  If it is, and @abortstr is non-NULL,
 * that will be printed and abort() is called.  Otherwise, if
 * @abortstr is NULL then the returned timemono will be normalized and
 * tv_sec set to 0 if it was negative.
 *
 * Note that if ccan/time is compiled with DEBUG, then it will call this
 * for all passed and returned times.
 *
 * Example:
 *	printf("Now is %lu seconds since mono start\n",
 *		(long)timemono_check(time_mono(), "time_mono failed?").ts.tv_sec);
 */
struct timemono timemono_check(struct timemono in, const char *abortstr);

/**
 * time_now - return the current time
 *
 * Example:
 *	printf("Now is %lu seconds since epoch\n", (long)time_now().ts.tv_sec);
 */
struct timeabs time_now(void);

/**
 * time_mono - return the current monotonic time
 *
 * This value is only really useful for measuring time intervals.
 *
 * See also:
 *	timemono_since()
 */
struct timemono time_mono(void);

static inline bool time_greater_(struct timespec a, struct timespec b)
{
	if (TIME_CHECK(a).tv_sec > TIME_CHECK(b).tv_sec)
		return true;
	else if (a.tv_sec < b.tv_sec)
		 return false;

	return a.tv_nsec > b.tv_nsec;
}

/**
 * time_after - is a after b?
 * @a: one abstime.
 * @b: another abstime.
 *
 * Example:
 *	static bool timed_out(const struct timeabs *start)
 *	{
 *	#define TIMEOUT time_from_msec(1000)
 *		return time_after(time_now(), timeabs_add(*start, TIMEOUT));
 *	}
 */
static inline bool time_after(struct timeabs a, struct timeabs b)
{
	return time_greater_(a.ts, b.ts);
}

/**
 * time_greater - is a greater than b?
 * @a: one reltime.
 * @b: another reltime.
 */
static inline bool time_greater(struct timerel a, struct timerel b)
{
	return time_greater_(a.ts, b.ts);
}

static inline bool time_less_(struct timespec a, struct timespec b)
{
	if (TIME_CHECK(a).tv_sec < TIME_CHECK(b).tv_sec)
		return true;
	else if (a.tv_sec > b.tv_sec)
		 return false;

	return a.tv_nsec < b.tv_nsec;
}

/**
 * time_before - is a before b?
 * @a: one absolute time.
 * @b: another absolute time.
 *
 * Example:
 *	static bool still_valid(const struct timeabs *start)
 *	{
 *	#define TIMEOUT time_from_msec(1000)
 *		return time_before(time_now(), timeabs_add(*start, TIMEOUT));
 *	}
 */
static inline bool time_before(struct timeabs a, struct timeabs b)
{
	return time_less_(a.ts, b.ts);
}

/**
 * time_less - is a before b?
 * @a: one relative time.
 * @b: another relative time.
 */
static inline bool time_less(struct timerel a, struct timerel b)
{
	return time_less_(a.ts, b.ts);
}

/**
 * timeabs_eq - is a equal to b?
 * @a: one absolute time.
 * @b: another absolute time.
 *
 * Example:
 *	#include <sys/types.h>
 *	#include <sys/wait.h>
 *
 *	// Can we fork in under a nanosecond?
 *	static bool fast_fork(void)
 *	{
 *		struct timeabs start = time_now();
 *		if (fork() != 0) {
 *			exit(0);
 *		}
 *		wait(NULL);
 *		return timeabs_eq(start, time_now());
 *	}
 */
static inline bool timeabs_eq(struct timeabs a, struct timeabs b)
{
	return TIMEABS_CHECK(a).ts.tv_sec == TIMEABS_CHECK(b).ts.tv_sec
		&& a.ts.tv_nsec == b.ts.tv_nsec;
}

/**
 * timemono_eq - is a equal to b?
 * @a: one monotonic time.
 * @b: another monotonic time.
 *
 * Example:
 *	#include <sys/types.h>
 *	#include <sys/wait.h>
 *
 *	// Can we fork in under a nanosecond?
 *	static bool fast_fork(void)
 *	{
 *		struct timemono start = time_mono();
 *		if (fork() != 0) {
 *			exit(0);
 *		}
 *		wait(NULL);
 *		return timemono_eq(start, time_mono());
 *	}
 */
static inline bool timemono_eq(struct timemono a, struct timemono b)
{
	return TIMEMONO_CHECK(a).ts.tv_sec == TIMEMONO_CHECK(b).ts.tv_sec
		&& a.ts.tv_nsec == b.ts.tv_nsec;
}

/**
 * timerel_eq - is a equal to b?
 * @a: one relative time.
 * @b: another relative time.
 *
 * Example:
 *	#include <sys/types.h>
 *	#include <sys/wait.h>
 *
 *	// Can we fork in under a nanosecond?
 *	static bool fast_fork(void)
 *	{
 *		struct timeabs start = time_now();
 *		struct timerel diff, zero = { .ts = { 0, 0 } };
 *		if (fork() != 0) {
 *			exit(0);
 *		}
 *		wait(NULL);
 *		diff = time_between(time_now(), start);
 *		return timerel_eq(diff, zero);
 *	}
 */
static inline bool timerel_eq(struct timerel a, struct timerel b)
{
	return TIMEREL_CHECK(a).ts.tv_sec == TIMEREL_CHECK(b).ts.tv_sec
		&& a.ts.tv_nsec == b.ts.tv_nsec;
}

static inline struct timespec time_sub_(struct timespec recent,
					struct timespec old)
{
	struct timespec diff;

	diff.tv_sec = TIME_CHECK(recent).tv_sec - TIME_CHECK(old).tv_sec;
	if (old.tv_nsec > recent.tv_nsec) {
		diff.tv_sec--;
		diff.tv_nsec = 1000000000 + recent.tv_nsec - old.tv_nsec;
	} else
		diff.tv_nsec = recent.tv_nsec - old.tv_nsec;

	return TIME_CHECK(diff);
}

/**
 * time_sub - subtract two relative times
 * @a: the larger time.
 * @b: the smaller time.
 *
 * This returns a well formed struct timerel of @a - @b.
 */
static inline struct timerel time_sub(struct timerel a, struct timerel b)
{
	struct timerel t;

	t.ts = time_sub_(a.ts, b.ts);
	return t;
}

/**
 * time_between - time between two absolute times
 * @recent: the larger time.
 * @old: the smaller time.
 *
 * This returns a well formed struct timerel of @a - @b.
 */
static inline struct timerel time_between(struct timeabs recent, struct timeabs old)
{
	struct timerel t;

	t.ts = time_sub_(recent.ts, old.ts);
	return t;
}

/**
 * timemono_between - time between two monotonic times
 * @recent: the larger time.
 * @old: the smaller time.
 *
 * This returns a well formed struct timerel of @recent - @old.
 */
static inline struct timerel timemono_between(struct timemono recent,
					      struct timemono old)
{
	struct timerel t;

	t.ts = time_sub_(recent.ts, old.ts);
	return t;
}

/**
 * timemono_since - elapsed monotonic time since @old
 * @old: a monotonic time from the past.
 */
static inline struct timerel timemono_since(struct timemono old)
{
	struct timemono now = time_mono();

	return timemono_between(now, TIMEMONO_CHECK(old));
}

/**
 * timeabs_sub - subtract a relative time from an absolute time
 * @abs: the absolute time.
 * @rel: the relative time.
 *
 * This returns a well formed struct timeabs of @a - @b.
 *
 * Example:
 *	// We do one every second.
 *	static struct timeabs previous_time(void)
 *	{
 *		return timeabs_sub(time_now(), time_from_msec(1000));
 *	}
 */
static inline struct timeabs timeabs_sub(struct timeabs abs, struct timerel rel)
{
	struct timeabs t;

	t.ts = time_sub_(abs.ts, rel.ts);
	return t;
}

static inline struct timespec time_add_(struct timespec a, struct timespec b)
{
	struct timespec sum;

	sum.tv_sec = TIME_CHECK(a).tv_sec + TIME_CHECK(b).tv_sec;
	sum.tv_nsec = a.tv_nsec + b.tv_nsec;
	if (sum.tv_nsec >= 1000000000) {
		sum.tv_sec++;
		sum.tv_nsec -= 1000000000;
	}
	return TIME_CHECK(sum);
}

/**
 * timeabs_add - add a relative to an absolute time
 * @a: the absolute time.
 * @b: a relative time.
 *
 * The times must not overflow, or the results are undefined.
 *
 * Example:
 *	// We do one every second.
 *	static struct timeabs next_time(void)
 *	{
 *		return timeabs_add(time_now(), time_from_msec(1000));
 *	}
 */
static inline struct timeabs timeabs_add(struct timeabs a, struct timerel b)
{
	struct timeabs t;

	t.ts = time_add_(a.ts, b.ts);
	return t;
}

/**
 * timemono_add - add a relative to a monotonic time
 * @a: the monotonic time.
 * @b: a relative time.
 *
 * The times must not overflow, or the results are undefined.
 *
 * Example:
 *	// We do one every second.
 *	static struct timemono next_timem(void)
 *	{
 *		return timemono_add(time_mono(), time_from_msec(1000));
 *	}
 */
static inline struct timemono timemono_add(struct timemono a, struct timerel b)
{
	struct timemono t;

	t.ts = time_add_(a.ts, b.ts);
	return t;
}

/**
 * timerel_add - add two relative times
 * @a: one relative time.
 * @b: another relative time.
 *
 * The times must not overflow, or the results are undefined.
 *
 * Example:
 *	static struct timerel double_time(struct timerel a)
 *	{
 *		return timerel_add(a, a);
 *	}
 */
static inline struct timerel timerel_add(struct timerel a, struct timerel b)
{
	struct timerel t;

	t.ts = time_add_(a.ts, b.ts);
	return t;
}

/**
 * time_divide - divide a time by a value.
 * @t: a time.
 * @div: number to divide it by.
 *
 * Example:
 *	// How long does it take to do a fork?
 *	static struct timerel forking_time(void)
 *	{
 *		struct timeabs start = time_now();
 *		unsigned int i;
 *
 *		for (i = 0; i < 1000; i++) {
 *			if (fork() != 0) {
 *				exit(0);
 *			}
 *			wait(NULL);
 *		}
 *		return time_divide(time_between(time_now(), start), i);
 *	}
 */
struct timerel time_divide(struct timerel t, unsigned long div);

/**
 * time_multiply - multiply a time by a value.
 * @t: a relative time.
 * @mult: number to multiply it by.
 *
 * Example:
 *	...
 *	printf("Time to do 100000 forks would be %u sec\n",
 *	       (unsigned)time_multiply(forking_time(), 1000000).ts.tv_sec);
 */
struct timerel time_multiply(struct timerel t, unsigned long mult);

/**
 * time_to_sec - return number of seconds
 * @t: a time
 *
 * It's often more convenient to deal with time values as seconds.
 * Note that this will fit into an unsigned 32-bit variable if it's a
 * time of less than about 136 years.
 *
 * Example:
 *	...
 *	printf("Forking time is %u sec\n",
 *	       (unsigned)time_to_sec(forking_time()));
 */
static inline uint64_t time_to_sec(struct timerel t)
{
	return t.ts.tv_sec;
}

/**
 * time_to_msec - return number of milliseconds
 * @t: a relative time
 *
 * It's often more convenient to deal with time values as
 * milliseconds.  Note that this will fit into a 32-bit variable if
 * it's a time difference of less than ~7 weeks.
 *
 * Example:
 *	...
 *	printf("Forking time is %u msec\n",
 *	       (unsigned)time_to_msec(forking_time()));
 */
static inline uint64_t time_to_msec(struct timerel t)
{
	uint64_t msec;

	msec = TIMEREL_CHECK(t).ts.tv_nsec/1000000 + (uint64_t)t.ts.tv_sec*1000;
	return msec;
}

/**
 * time_to_usec - return number of microseconds
 * @t: a relative time
 *
 * It's often more convenient to deal with time values as
 * microseconds.  Note that this will fit into a 32-bit variable if
 * it's a time difference of less than ~1 hour.
 *
 * Example:
 *	...
 *	printf("Forking time is %u usec\n",
 *	       (unsigned)time_to_usec(forking_time()));
 *
 */
static inline uint64_t time_to_usec(struct timerel t)
{
	uint64_t usec;

	usec = TIMEREL_CHECK(t).ts.tv_nsec/1000 + (uint64_t)t.ts.tv_sec*1000000;
	return usec;
}

/**
 * time_to_nsec - return number of nanoseconds
 * @t: a relative time
 *
 * It's sometimes more convenient to deal with time values as
 * nanoseconds.  Note that this will fit into a 32-bit variable if
 * it's a time difference of less than ~4 seconds.
 *
 * Example:
 *	...
 *	printf("Forking time is %u nsec\n",
 *	       (unsigned)time_to_nsec(forking_time()));
 *
 */
static inline uint64_t time_to_nsec(struct timerel t)
{
	uint64_t nsec;

	nsec = TIMEREL_CHECK(t).ts.tv_nsec + (uint64_t)t.ts.tv_sec * 1000000000;
	return nsec;
}

/**
 * time_from_sec - convert seconds to a relative time
 * @msec: time in seconds
 *
 * Example:
 *	// 1 minute timeout
 *	#define TIMEOUT time_from_sec(60)
 */
static inline struct timerel time_from_sec(uint64_t sec)
{
	struct timerel t;

	t.ts.tv_nsec = 0;
	t.ts.tv_sec = sec;
	return TIMEREL_CHECK(t);
}

/**
 * time_from_msec - convert milliseconds to a relative time
 * @msec: time in milliseconds
 *
 * Example:
 *	// 1/2 second timeout
 *	#define TIMEOUT time_from_msec(500)
 */
static inline struct timerel time_from_msec(uint64_t msec)
{
	struct timerel t;

	t.ts.tv_nsec = (msec % 1000) * 1000000;
	t.ts.tv_sec = msec / 1000;
	return TIMEREL_CHECK(t);
}

/**
 * time_from_usec - convert microseconds to a relative time
 * @usec: time in microseconds
 *
 * Example:
 *	// 1/2 second timeout
 *	#define TIMEOUT time_from_usec(500000)
 */
static inline struct timerel time_from_usec(uint64_t usec)
{
	struct timerel t;

	t.ts.tv_nsec = (usec % 1000000) * 1000;
	t.ts.tv_sec = usec / 1000000;
	return TIMEREL_CHECK(t);
}

/**
 * time_from_nsec - convert nanoseconds to a relative time
 * @nsec: time in nanoseconds
 *
 * Example:
 *	// 1/2 second timeout
 *	#define TIMEOUT time_from_nsec(500000000)
 */
static inline struct timerel time_from_nsec(uint64_t nsec)
{
	struct timerel t;

	t.ts.tv_nsec = nsec % 1000000000;
	t.ts.tv_sec = nsec / 1000000000;
	return TIMEREL_CHECK(t);
}

static inline struct timeval timespec_to_timeval(struct timespec ts)
{
	struct timeval tv;
	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = ts.tv_nsec / 1000;
	return tv;
}

/**
 * timerel_to_timeval - convert a relative time to a timeval.
 * @t: a relative time.
 *
 * Example:
 *	struct timerel t = { { 100, 0 } }; // 100 seconds
 *	struct timeval tv;
 *
 *	tv = timerel_to_timeval(t);
 *	printf("time = %lu.%06u\n", (long)tv.tv_sec, (int)tv.tv_usec);
 */
static inline struct timeval timerel_to_timeval(struct timerel t)
{
	return timespec_to_timeval(t.ts);
}

/**
 * timeabs_to_timeval - convert an absolute time to a timeval.
 * @t: an absolute time.
 *
 * Example:
 *	struct timeval tv;
 *
 *	tv = timeabs_to_timeval(time_now());
 *	printf("time = %lu.%06u\n", (long)tv.tv_sec, (int)tv.tv_usec);
 */
static inline struct timeval timeabs_to_timeval(struct timeabs t)
{
	return timespec_to_timeval(t.ts);
}

static inline struct timespec timeval_to_timespec(struct timeval tv)
{
	struct timespec ts;
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
	return ts;
}

/**
 * timeval_to_timerel - convert a timeval to a relative time.
 * @tv: a timeval.
 *
 * Example:
 *	struct timeval tv = { 0, 500 };
 *	struct timerel t;
 *
 *	t = timeval_to_timerel(tv);
 *	printf("timerel = %lu.%09lu\n", (long)t.ts.tv_sec, (long)t.ts.tv_nsec);
 */
static inline struct timerel timeval_to_timerel(struct timeval tv)
{
	struct timerel t;
	t.ts = timeval_to_timespec(tv);
	return TIMEREL_CHECK(t);
}

/**
 * timeval_to_timeabs - convert a timeval to an absolute time.
 * @tv: a timeval.
 *
 * Example:
 *	struct timeval tv = { 1401762008, 500 };
 *	struct timeabs t;
 *
 *	t = timeval_to_timeabs(tv);
 *	printf("timeabs = %lu.%09lu\n", (long)t.ts.tv_sec, (long)t.ts.tv_nsec);
 */
static inline struct timeabs timeval_to_timeabs(struct timeval tv)
{
	struct timeabs t;
	t.ts = timeval_to_timespec(tv);
	return TIMEABS_CHECK(t);
}
#endif /* CCAN_TIME_H */
