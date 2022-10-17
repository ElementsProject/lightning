#ifndef LIGHTNING_COMMON_HSM_VERSION_H
#define LIGHTNING_COMMON_HSM_VERSION_H
#include "config.h"

/* We give a maximum and minimum compatibility version to HSM, to allow
 * some API adaptation. */

/* wire/hsmd_wire.csv contents version:
 *    409cffa355ab6cc76bd298910adca9936a68223267ddc4815ba16aeac5d0acc3
 */
#define HSM_MIN_VERSION 1

/* wire/hsmd_wire.csv contents version:
 *    43c435f61de3af0dd7a91514d94b3e0762c962fce5b39be430538f8c6c4b0695
 */
#define HSM_MAX_VERSION 2
#endif /* LIGHTNING_COMMON_HSM_VERSION_H */
