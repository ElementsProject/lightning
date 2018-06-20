#include <assert.h>
#include <ccan/noerr/noerr.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <fcntl.h>
#include <lightningd/app_connection.h>
#include <lightningd/channel.h>
#include <lightningd/htlc_end.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
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
	/* The app could not be run. */
	APP_NOT_RUN = 3,
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
		result = APP_NOT_RUN;
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
	struct log *log = hin->key.channel->log;
	struct lightningd *ld = hin->key.channel->peer->ld;
	char *configdir = ld->config_dir;
	char *command = tal_fmt(tmpctx, "handle_realm_%d", rs->hop_data.realm);

	log_debug(log, "Trying to run app command \"%s\"", command);
	pid = start_cmd(configdir, command, &msgfd, &resultfd);

	if (pid < 0) {
		log_unusual(log, "Failed to fork - app script not run");
		/* No command was started */
		result = APP_NOT_RUN;
	}

	/* FIXME: write data to msgfd */
	close_noerr(msgfd);

	/* FIXME: don't hang on blocking reads */
	if (result == APP_UNKNOWN && read(resultfd, &result, 1) < 0) {
		log_unusual(log, "Failed to read result from app script");
	}
	close_noerr(resultfd);

	/* FIXME: don't hang on non-halting commands */
	waitpid(pid, NULL, 0);
	//FIXME: log nonzero exit status

	switch(result)
	{
	case APP_NOT_FORWARDED:
		log_debug(log, "App command failed to forward the payment");
		/* FIXME: other failcode: it's not the realm that is invalid */
		*failcode = WIRE_INVALID_REALM;
		break;
	case APP_NOT_RUN:
		log_debug(log, "Failed to run command \"%s\" from directory \"%s\"",
			command, configdir);
		*failcode = WIRE_INVALID_REALM;
		break;
	case APP_UNKNOWN:
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
		log_unusual(log, "App command did not report whether it forwarded the payment; keeping the incoming HTLC for now");
		*failcode = 0;
		break;
	case APP_FORWARDED:
		*failcode = 0;
		break;
	}
}

