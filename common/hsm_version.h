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
 *    edd3d288fc88a5470adc2f99abcbfe4d4af29fae0c7a80b4226f28810a815524
 */
#define HSM_MAX_VERSION 3
#endif /* LIGHTNING_COMMON_HSM_VERSION_H */
