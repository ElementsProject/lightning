#ifndef LIGHTNING_COMMON_ECDH_HSMD_H
#define LIGHTNING_COMMON_ECDH_HSMD_H
#include "config.h"
#include <common/ecdh.h>
#include <common/status_levels.h>

/* The via-the-hsmd implementation of ecdh(). */

/* You must call this before calling ecdh(). */
void ecdh_hsmd_setup(int hsm_fd,
		     void (*failed)(enum status_failreason,
				    const char *fmt, ...));
#endif /* LIGHTNING_COMMON_ECDH_HSMD_H */
