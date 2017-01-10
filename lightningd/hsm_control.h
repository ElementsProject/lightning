#ifndef LIGHTNING_LIGHTNINGD_HSM_CONTROL_H
#define LIGHTNING_LIGHTNINGD_HSM_CONTROL_H
#include "config.h"
#include <stdbool.h>

struct lightningd;

void hsm_init(struct lightningd *ld, bool newdir);
#endif /* LIGHTNING_LIGHTNINGD_HSM_CONTROL_H */
