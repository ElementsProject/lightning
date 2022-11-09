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
 *    dd89bf9323dff42200003fb864abb6608f3aa645b636fdae3ec81d804ac05196
 */
#define HSM_MAX_VERSION 2
#endif /* LIGHTNING_COMMON_HSM_VERSION_H */
