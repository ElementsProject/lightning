#ifndef LIGHTNING_PLUGINS_OFFERS_PROOF_H
#define LIGHTNING_PLUGINS_OFFERS_PROOF_H
#include "config.h"

struct command_result;
struct command;

struct command_result *json_createproof(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_OFFERS_PROOF_H */
