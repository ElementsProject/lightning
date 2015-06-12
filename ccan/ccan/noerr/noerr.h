/* CC0 (Public domain) - see LICENSE file for details */
#ifndef NOERR_H
#define NOERR_H
#include <stdio.h>

/**
 * close_noerr - close without stomping errno.
 * @fd: the file descriptor to close.
 *
 * errno is saved and restored across the call to close: if an error occurs,
 * the resulting (non-zero) errno is returned.
 */
int close_noerr(int fd);

/**
 * fclose_noerr - close without stomping errno.
 * @fp: the FILE pointer.
 *
 * errno is saved and restored across the call to fclose: if an error occurs,
 * the resulting (non-zero) errno is returned.
 */
int fclose_noerr(FILE *fp);

/**
 * unlink_noerr - unlink a file without stomping errno.
 * @pathname: the path to unlink.
 *
 * errno is saved and restored across the call to unlink: if an error occurs,
 * the resulting (non-zero) errno is returned.
 */
int unlink_noerr(const char *pathname);

#endif /* NOERR_H */
