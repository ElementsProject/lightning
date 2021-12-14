#ifndef LIGHTNING_COMMON_ERRCODE_H
#define LIGHTNING_COMMON_ERRCODE_H

#include "config.h"

#include <ccan/short_types/short_types.h>

typedef s32 errcode_t;

#define PRIerrcode PRId32

// HSM errors code
#define HSM_GENERIC_ERROR 20
#define HSM_ERROR_IS_ENCRYPT 21
#define HSM_BAD_PASSWORD 22
#define HSM_PASSWORD_INPUT_ERR 23

#endif /* LIGHTNING_COMMON_ERRCODE_H */
