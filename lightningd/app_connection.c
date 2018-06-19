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

static bool move_fd(int from, int to)
{
	assert(from >= 0);
	if (dup2(from, to) == -1)
		return false;
	close(from);
	return true;
}

static int start_cmd(const char *dir, const char *name, int *msgfd)
{
	int childmsg[2];
	pid_t childpid;

	if (pipe(childmsg) != 0)
		goto fail;

	if (fcntl(childmsg[1], F_SETFD, fcntl(childmsg[1], F_GETFD)
		  | FD_CLOEXEC) < 0)
		goto close_msgfd_fail;

	childpid = fork();
	if (childpid < 0)
		goto close_msgfd_fail;

	if (childpid == 0) {
		int fdnum = 3, i;
		long max;
		char *args[] = {NULL, NULL};

		close(childmsg[0]);

		// msg = STDIN
		if (childmsg[1] != STDIN_FILENO) {
			if (!move_fd(childmsg[1], STDIN_FILENO))
				goto child_fail;
		}

		/* Make (fairly!) sure all other fds are closed. */
		max = sysconf(_SC_OPEN_MAX);
		for (i = fdnum; i < max; i++)
			close(i);

		args[0] = path_join(NULL, dir, name);
		execv(args[0], args);

	child_fail:
		exit(127);
	}

	close(childmsg[1]);

	*msgfd = childmsg[0];
	return childpid;

close_msgfd_fail:
	close_noerr(childmsg[0]);
	close_noerr(childmsg[1]);
fail:
	return -1;
}

void handle_app_payment(
	enum onion_type *failcode,
	const struct htlc_in *hin,
	const struct route_step *rs)
{
	int pid;
	int msgfd;

	log_debug(hin->key.channel->log, "Trying to run app script for realm %d",
		  rs->hop_data.realm);

	/* FIXME: use sensible directory and command name */
	pid = start_cmd(".", "app_connection", &msgfd);

	if (pid < 0) {
		//FIXME: log failure
		/*
		No command was started, so we can safely reject the
		incoming funds.
		*/
		*failcode = WIRE_INVALID_REALM;
		return;
	}

	/* FIXME: write data to msgfd */
	close_noerr(msgfd);

	/* FIXME: don't hang on non-halting commands */
	waitpid(pid, NULL, 0);
	//FIXME: log nonzero exit status

	/*
	Note:
	If anything indicates a failure of the command, at this point,
	we still cannot safely reject the incoming HTLC: before failure,
	the command might have done someting that makes the transaction succeed.
	If the higher-level application (to which the command belongs) knows the
	transaction is guaranteed to fail, it must manually instruct lightningd
	to remove the incoming HTLC.
	For now, however, we must accept it unconditionally.
	*/

	*failcode = 0;
}

