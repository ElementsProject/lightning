#ifndef LIGHTNING_PLUGINS_FETCHINVOICE_H
#define LIGHTNING_PLUGINS_FETCHINVOICE_H
#include "config.h"

struct command_result;
struct command;

struct command_result *json_fetchinvoice(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *params);

struct command_result *json_sendinvoice(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params);

struct command_result *json_dev_rawrequest(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *params);

struct command_result *recv_modern_onion_message(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params);
struct command_result *invoice_payment(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_FETCHINVOICE_H */
