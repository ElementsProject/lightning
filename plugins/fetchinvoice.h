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

/* Returns NULL if this wasn't one of ours. */
struct command_result *handle_invoice_onion_message(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *om,
						    const struct secret *pathsecret);

/* invoice_payment hook */
struct command_result *invoice_payment(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_FETCHINVOICE_H */
