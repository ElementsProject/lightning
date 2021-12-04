/* CC0 license (public domain) - see LICENSE file for details */
#ifndef CCAN_PIPECMD_H
#define CCAN_PIPECMD_H
#include "config.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>

/**
 * pipecmd - run a command, optionally connect pipes.
 * @infd: input fd to write to child (if non-NULL)
 * @outfd: output fd to read from child (if non-NULL)
 * @errfd: error-output fd to read from child (if non-NULL)
 * @cmd...: NULL-terminate list of command and arguments.
 *
 * If @infd is NULL, the child's input is (read-only) /dev/null.
 * If @outfd is NULL, the child's output is (write-only) /dev/null.
 * If @errfd is NULL, the child's stderr is (write-only) /dev/null.
 *
 * If @errfd == @outfd (and non-NULL) they will be shared.
 * If @infd, @outfd or @errfd is &pipecmd_preserve, it is unchanged.
 *
 * The return value is the pid of the child, or -1.  All other file-descriptors
 * are closed in the child.
 */
pid_t pipecmd(int *infd, int *outfd, int *errfd, const char *cmd, ...);

/**
 * pipecmdv - run a command, optionally connect pipes (stdarg version)
 * @infd: input fd to write to child (if non-NULL)
 * @outfd: output fd to read from child (if non-NULL)
 * @errfd: error-output fd to read from child (if non-NULL)
 * @cmd: command to run.
 * @ap: argument list for arguments.
 */
pid_t pipecmdv(int *infd, int *outfd, int *errfd, const char *cmd, va_list ap);

/**
 * pipecmdarr - run a command, optionally connect pipes (char arry version)
 * @infd: input fd to write to child (if non-NULL)
 * @outfd: output fd to read from child (if non-NULL)
 * @errfd: error-output fd to read from child (if non-NULL)
 * @arr: NULL-terminated array for arguments (first is program to run).
 */
pid_t pipecmdarr(int *infd, int *outfd, int *errfd, char *const *arr);

/**
 * pipecmd_preserve - special value for fds to indicate it is unchanged
 */
extern int pipecmd_preserve;

#endif /* CCAN_PIPECMD_H */
