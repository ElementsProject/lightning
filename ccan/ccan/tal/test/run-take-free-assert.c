#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	int status;
	char *p;

	plan_tests(4);

	/* Test direct free. */
	switch (fork()) {
	case 0:
		tal_free(take(tal(NULL, char)));
		exit(2);
	case -1:
		exit(1);
	default:
		wait(&status);
		ok1(WIFSIGNALED(status));
		ok1(WTERMSIG(status) == SIGABRT);
	}

	/* Test indirect free. */
	switch (fork()) {
	case 0:
		p = tal(NULL, char);
		take(tal(p, char));
		tal_free(p);
		exit(2);
	case -1:
		exit(1);
	default:
		wait(&status);
		ok1(WIFSIGNALED(status));
		ok1(WTERMSIG(status) == SIGABRT);
	}
	return exit_status();
}
