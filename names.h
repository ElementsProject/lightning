#ifndef LIGHTNING_NAMES_H
#define LIGHTNING_NAMES_H
#include "config.h"
#include "lightning.pb-c.h"
#include "state_types.h"

const char *state_name(enum state s);
const char *input_name(enum state_input in);
const char *cstatus_name(enum command_status cstatus);
const char *peercond_name(enum state_peercond peercond);
const char *pkt_name(Pkt__PktCase pkt);
#endif /* LIGHTNING_NAMES_H */
