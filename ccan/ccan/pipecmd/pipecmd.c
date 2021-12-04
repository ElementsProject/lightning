/* CC0 license (public domain) - see LICENSE file for details */
#include <ccan/closefrom/closefrom.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/noerr/noerr.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

int pipecmd_preserve;

static char **gather_args(const char *arg0, va_list ap)
{
	size_t n = 1;
	char **arr = calloc(sizeof(char *), n + 1);

	if (!arr)
		return NULL;
	arr[0] = (char *)arg0;

	while ((arr[n++] = va_arg(ap, char *)) != NULL) {
		char **narr = realloc(arr, sizeof(char *) * (n + 1));
		if (!narr) {
			free(arr);
			return NULL;
		}
		arr = narr;
	}
	return arr;
}

pid_t pipecmdv(int *fd_tochild, int *fd_fromchild, int *fd_errfromchild,
	       const char *cmd, va_list ap)
{
	char **arr = gather_args(cmd, ap);
	pid_t ret;

	if (!arr) {
		errno = ENOMEM;
		return -1;
	}
	ret = pipecmdarr(fd_tochild, fd_fromchild, fd_errfromchild, arr);
	free_noerr(arr);
	return ret;
}

pid_t pipecmdarr(int *fd_tochild, int *fd_fromchild, int *fd_errfromchild,
		 char *const *arr)
{
	int tochild[2], fromchild[2], errfromchild[2], execfail[2];
	/* fds for parent to close */
	int par_close[4], num_par_close = 0;
	/* fds for child to close */
	int child_close[4], num_child_close = 0;
	pid_t childpid;
	int err;

	if (fd_tochild) {
		if (fd_tochild == &pipecmd_preserve) {
			tochild[0] = STDIN_FILENO;
		} else if (pipe(tochild) == 0) {
			par_close[num_par_close++] = tochild[0];
			child_close[num_child_close++] = tochild[1];
		} else
			goto fail;
	} else {
		tochild[0] = open("/dev/null", O_RDONLY);
		if (tochild[0] < 0)
			goto fail;
		par_close[num_par_close++] = tochild[0];
	}
	if (fd_fromchild) {
		if (fd_fromchild == &pipecmd_preserve) {
			fromchild[1] = STDOUT_FILENO;
		} else if (pipe(fromchild) == 0) {
			par_close[num_par_close++] = fromchild[1];
			child_close[num_child_close++] = fromchild[0];
		} else
			goto fail;
	} else {
		fromchild[1] = open("/dev/null", O_WRONLY);
		if (fromchild[1] < 0)
			goto fail;
		par_close[num_par_close++] = fromchild[1];
	}
	if (fd_errfromchild) {
		if (fd_errfromchild == &pipecmd_preserve) {
			errfromchild[1] = STDERR_FILENO;
		} else if (fd_errfromchild == fd_fromchild) {
			errfromchild[0] = fromchild[0];
			errfromchild[1] = fromchild[1];
		} else if (pipe(errfromchild) == 0) {
			par_close[num_par_close++] = errfromchild[1];
			child_close[num_child_close++] = errfromchild[0];
		} else
			goto fail;
	} else {
		errfromchild[1] = open("/dev/null", O_WRONLY);
		if (errfromchild[1] < 0)
			goto fail;
		par_close[num_par_close++] = errfromchild[1];
	}

	if (pipe(execfail) != 0)
		goto fail;

	par_close[num_par_close++] = execfail[1];
	child_close[num_child_close++] = execfail[0];

	if (fcntl(execfail[1], F_SETFD, fcntl(execfail[1], F_GETFD)
		  | FD_CLOEXEC) < 0)
		goto fail;

	childpid = fork();
	if (childpid < 0)
		goto fail;

	if (childpid == 0) {
		int i;
		for (i = 0; i < num_child_close; i++)
			close(child_close[i]);

		// Child runs command.
		if (tochild[0] != STDIN_FILENO) {
			if (dup2(tochild[0], STDIN_FILENO) == -1)
				goto child_errno_fail;
			close(tochild[0]);
		}
		if (fromchild[1] != STDOUT_FILENO) {
			if (dup2(fromchild[1], STDOUT_FILENO) == -1)
				goto child_errno_fail;
			close(fromchild[1]);
		}
		if (fd_errfromchild && fd_errfromchild == fd_fromchild) {
			if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1)
				goto child_errno_fail;
		} else if (errfromchild[1] != STDERR_FILENO) {
			if (dup2(errfromchild[1], STDERR_FILENO) == -1)
				goto child_errno_fail;
			close(errfromchild[1]);
		}

		/* Map execfail[1] to fd 3.  */
		if (execfail[1] != 3) {
			if (dup2(execfail[1], 3) == -1)
				goto child_errno_fail;
			/* CLOEXEC is not shared by dup2, so copy the flags
			 * from execfail[1] to 3.
			 */
			if (fcntl(3, F_SETFD, fcntl(execfail[1], F_GETFD)) < 0)
				goto child_errno_fail;
			close(execfail[1]);
			execfail[1] = 3;
		}

		/* Make (fairly!) sure all other fds are closed. */
		closefrom(4);

		execvp(arr[0], arr);

	child_errno_fail:
		err = errno;
		/* Gcc's warn-unused-result fail. */
		if (write(execfail[1], &err, sizeof(err))) {
			;
		}
		exit(127);
	}

	int i;
	for (i = 0; i < num_par_close; i++)
		close(par_close[i]);

	/* Child will close this without writing on successful exec. */
	if (read(execfail[0], &err, sizeof(err)) == sizeof(err)) {
		close(execfail[0]);
		waitpid(childpid, NULL, 0);
		errno = err;
		return -1;
	}
	close(execfail[0]);
	if (fd_tochild && fd_tochild != &pipecmd_preserve)
		*fd_tochild = tochild[1];
	if (fd_fromchild && fd_fromchild != &pipecmd_preserve)
		*fd_fromchild = fromchild[0];
	if (fd_errfromchild && fd_errfromchild != &pipecmd_preserve)
		*fd_errfromchild = errfromchild[0];
	return childpid;

fail:
	for (i = 0; i < num_par_close; i++)
		close_noerr(par_close[i]);
	return -1;
}

pid_t pipecmd(int *fd_tochild, int *fd_fromchild, int *fd_errfromchild,
	      const char *cmd, ...)
{
	pid_t childpid;

	va_list ap;
	va_start(ap, cmd);
	childpid = pipecmdv(fd_tochild, fd_fromchild, fd_errfromchild, cmd, ap);
	va_end(ap);

	return childpid;
}
