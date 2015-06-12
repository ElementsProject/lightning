/* Licensed under LGPLv2+ - see LICENSE file for details */
#ifndef _CCAN_READ_WRITE_H
#define _CCAN_READ_WRITE_H
#include <stddef.h>
#include <stdbool.h>

bool write_all(int fd, const void *data, size_t size);
bool read_all(int fd, void *data, size_t size);

#endif /* _CCAN_READ_WRITE_H */
