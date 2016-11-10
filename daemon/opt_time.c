#include "opt_time.h"
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

static bool match(const char *str, const char *abbrev, const char *full)
{
	if (streq(str, abbrev))
		return true;

	if (streq(str, full))
		return true;

	/* Allow "seconds" */
	if (memcmp(str, full, strlen(full)) == 0
	    && streq(str + strlen(full), "s"))
		return true;

	return false;
}

char *opt_set_time(const char *arg, struct timerel *t)
{
	char *endp;
	unsigned long int l;

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtol(arg, &endp, 0);
	if (endp == arg)
		return tal_fmt(NULL, "'%s' is not a number", arg);
	if (errno)
		return tal_fmt(NULL, "'%s' is out of range", arg);

	while (isspace(*endp))
		endp++;

	if (match(endp, "s", "second"))
		*t = time_from_sec(l);
	else if (match(endp, "m", "minute"))
		*t = time_from_sec(l * 60);
	else if (match(endp, "h", "hour"))
		*t = time_from_sec(l * 60 * 60);
	else if (match(endp, "d", "day"))
		*t = time_from_sec(l * 60 * 60 * 24);
	else if (match(endp, "ms", "millisecond"))
		*t = time_from_msec(l);
	else if (match(endp, "us", "microsecond"))
		*t = time_from_usec(l);
	else if (match(endp, "ns", "nanosecond"))
		*t = time_from_nsec(l);
	else
		return tal_fmt(NULL, "Unknown time unit %s", endp);
	return NULL;
}

void opt_show_time(char buf[OPT_SHOW_LEN], const struct timerel *t)
{
	if (t->ts.tv_nsec) {
		if (t->ts.tv_nsec % 1000)
			sprintf(buf, "%"PRIu64"ns", time_to_nsec(*t));
		else if (t->ts.tv_nsec % 1000000)
			sprintf(buf, "%"PRIu64"us", time_to_usec(*t));
		else
			sprintf(buf, "%"PRIu64"ms", time_to_msec(*t));
	} else if (t->ts.tv_sec) {
		if (t->ts.tv_sec % (60 * 60 * 24) == 0)
			sprintf(buf, "%lud", t->ts.tv_sec / (60 * 60 * 24));
		else if (t->ts.tv_sec % (60 * 60) == 0)
			sprintf(buf, "%luh", t->ts.tv_sec / (60 * 60));
		else if (t->ts.tv_sec % 60 == 0)
			sprintf(buf, "%lum", t->ts.tv_sec / 60);
		else
			sprintf(buf, "%lus", t->ts.tv_sec);
	} else
		sprintf(buf, "%lus", t->ts.tv_sec);
}

char *opt_set_timeabs(const char *arg, struct timeabs *t)
{
	long double d;

	if (sscanf(arg, "%Lf", &d) != 1)
		return tal_fmt(NULL, "'%s' is not a time", arg);
	t->ts.tv_sec = d;
	t->ts.tv_nsec = (d - t->ts.tv_sec) * 1000000000;
	return NULL;
}

void opt_show_timeabs(char buf[OPT_SHOW_LEN], const struct timeabs *t)
{
	long double d = t->ts.tv_sec;
	d = d * 1000000000 + t->ts.tv_nsec;

	sprintf(buf, "%.9Lf", d);
}
