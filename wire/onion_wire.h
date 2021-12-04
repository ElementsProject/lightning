#ifndef LIGHTNING_WIRE_ONION_WIRE_H
#define LIGHTNING_WIRE_ONION_WIRE_H
#include "config.h"
#include <stdbool.h>

#if EXPERIMENTAL_FEATURES
#include <wire/onion_exp_wiregen.h>
#else
#include <wire/onion_wiregen.h>
#endif

#endif /* LIGHTNING_WIRE_ONION_WIRE_H */
