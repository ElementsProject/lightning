#include <assert.h>
#include <ccan/noerr/noerr.h>
#include <ccan/tal/path/path.h>
#include <fcntl.h>
#include <lightningd/app_connection.h>
#include <lightningd/channel.h>
#include <lightningd/htlc_end.h>
#include <lightningd/log.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum app_result_type {
	/* The app forwarded the payment. */
	APP_FORWARDED = 0,
	/* The app did not forward the payment. */
	APP_NOT_FORWARDED = 1,
	/* It is unknown whether the app forwarded the payment. */
	APP_UNKNOWN = 2,
};

static bool move_fd(int from, int to)
{
	assert(from >= 0);
	if (dup2(from, to) == -1)
		return false;
	close(from);
	return true;
}

static int start_cmd(const char *dir, const char *name, int *msgfd, int *resultfd)
{
	int childresult[2];
	int childmsg[2];
	pid_t childpid;

	if (pipe(childresult) != 0)
		goto fail;

	if (pipe(childmsg) != 0)
		goto close_resultfd_fail;

	if (fcntl(childmsg[1], F_SETFD, fcntl(childmsg[1], F_GETFD)
		  | FD_CLOEXEC) < 0)
		goto close_fds_fail;

	if (fcntl(childresult[1], F_SETFD, fcntl(childresult[1], F_GETFD)
		  | FD_CLOEXEC) < 0)
		goto close_fds_fail;

	childpid = fork();
	if (childpid < 0)
		goto close_fds_fail;

	if (childpid == 0) {
		int fdnum = 3, i;
		long max;
		char *args[] = {NULL, NULL};
		u8 result;

		close(childmsg[0]);
		close(childresult[0]);

		// msg = STDIN
		if (childmsg[1] != STDIN_FILENO) {
			if (!move_fd(childmsg[1], STDIN_FILENO))
				goto child_fail;
			childmsg[1] = STDIN_FILENO;
		}

		// msg = STDOUT
		if (childresult[1] != STDOUT_FILENO) {
			if (!move_fd(childresult[1], STDOUT_FILENO))
				goto child_fail;
			childresult[1] = STDOUT_FILENO;
		}

		/* Make (fairly!) sure all other fds are closed. */
		max = sysconf(_SC_OPEN_MAX);
		for (i = fdnum; i < max; i++)
			close(i);

		args[0] = path_join(NULL, dir, name);
		execv(args[0], args);

	child_fail:
		result = APP_NOT_FORWARDED;
		write(childresult[1], &result, 1);
		exit(127);
	}

	close(childmsg[1]);
	close(childresult[1]);

	*msgfd = childmsg[0];
	*resultfd = childresult[0];
	return childpid;

close_fds_fail:
	close_noerr(childmsg[0]);
	close_noerr(childmsg[1]);

close_resultfd_fail:
	close_noerr(childresult[0]);
	close_noerr(childresult[1]);

fail:
	return -1;
}

void handle_app_payment(
	enum onion_type *failcode,
	const struct htlc_in *hin,
	const struct route_step *rs)
{
	int pid;
	int msgfd, resultfd;
	u8 result = APP_UNKNOWN;

	log_debug(hin->key.channel->log, "Trying to run app script for realm %d",
		  rs->hop_data.realm);

	/* FIXME: use sensible directory and command name */
	pid = start_cmd(".", "app_connection", &msgfd, &resultfd);

	if (pid < 0) {
		//FIXME: log failure
		/* No command was started */
		result = APP_NOT_FORWARDED;
	}

	/* FIXME: write data to msgfd */
	close_noerr(msgfd);

	/* FIXME: don't hang on blocking reads */
	if (result == APP_UNKNOWN && read(resultfd, &result, 1) < 0) {
		//FIXME: log failure
	}
	close_noerr(resultfd);

	/* FIXME: don't hang on non-halting commands */
	waitpid(pid, NULL, 0);
	//FIXME: log nonzero exit status

	if (result == APP_NOT_FORWARDED) {
		*failcode = WIRE_INVALID_REALM;
	} else {
		/*
		We can *only* safely reject the incoming HTLC if we are sure the
		command did not forward the payment.
		In case it is unknown, the command might have done someting that
		makes the transaction succeed, so we still need the incoming
		HTLC.
		If the higher-level application (to which the command belongs)
		knows the transaction is guaranteed to fail, it must manually
		instruct lightningd to remove the incoming HTLC.
		For now, however, we must accept it unconditionally.
		*/
		*failcode = 0;
	}
}

