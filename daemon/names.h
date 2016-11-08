#ifndef LIGHTNING_NAMES_H
#define LIGHTNING_NAMES_H
#include "config.h"
#include "lightning.pb-c.h"
#include "state_types.h"

const char *state_name(enum state s);
enum state name_to_state(const char *name);
const char *pkt_name(Pkt__PktCase pkt);
#endif /* LIGHTNING_NAMES_H */
