/* We expect a timer to rarely go off, so benchmark that case:
 * Every 1ms a connection comes in, we set up a 30 second timer for it.
 * After 8192ms we finish the connection (and thus delete the timer).
 */
#include <ccan/timer/timer.h>
#include <ccan/opt/opt.h>
#include <ccan/array_size/array_size.h>
#include <stdio.h>

#define PER_CONN_TIME 8192
#define CONN_TIMEOUT_MS 30000

int main(int argc, char *argv[])
{
	struct timespec start, curr;
	struct timers timers;
	struct list_head expired;
	struct timer t[PER_CONN_TIME];
	unsigned int i, num;
	bool check = false;

	opt_register_noarg("-c|--check", opt_set_bool, &check,
			   "Check timer structure during progress");

	opt_parse(&argc, argv, opt_log_stderr_exit);

	num = argv[1] ? atoi(argv[1]) : (check ? 100000 : 100000000);

	list_head_init(&expired);
	curr = start = time_now();
	timers_init(&timers, start);

	for (i = 0; i < num; i++) {
		curr = time_add(curr, time_from_msec(1));
		if (check)
			timers_check(&timers, NULL);
		if (timers_expire(&timers, curr))
			abort();
		if (check)
			timers_check(&timers, NULL);

		if (i >= PER_CONN_TIME) {
			timer_del(&timers, &t[i%PER_CONN_TIME]);
			if (check)
				timers_check(&timers, NULL);
		}
		timer_add(&timers, &t[i%PER_CONN_TIME],
			  time_add(curr, time_from_msec(CONN_TIMEOUT_MS)));
		if (check)
			timers_check(&timers, NULL);
	}
	if (num > PER_CONN_TIME) {
		for (i = 0; i < PER_CONN_TIME; i++)
			timer_del(&timers, &t[i]);
	}

	curr = time_sub(time_now(), start);
	if (check)
		timers_check(&timers, NULL);
	timers_cleanup(&timers);
	opt_free_table();

	for (i = 0; i < ARRAY_SIZE(timers.level); i++)
		if (!timers.level[i])
			break;

	printf("%u in %lu.%09lu (%u levels / %zu)\n",
	       num, (long)curr.tv_sec, curr.tv_nsec,
	       i, ARRAY_SIZE(timers.level));
	return 0;
}
