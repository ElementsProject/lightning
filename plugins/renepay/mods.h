#ifndef LIGHTNING_PLUGINS_RENEPAY_MODS_H
#define LIGHTNING_PLUGINS_RENEPAY_MODS_H

#include "config.h"

struct payment;
struct command_result;

struct payment_modifier {
	const char *name;
	struct command_result *(*step_cb)(struct payment *p);
};

struct payment_condition {
	const char *name;
	bool (*condition_cb)(const struct payment *p);
};

struct command_result *payment_continue(struct payment *p);

#define REGISTER_PAYMENT_MODIFIER(name, step_cb)                               \
	struct payment_modifier name##_pay_mod = {                             \
	    stringify(name),                                                   \
	    typesafe_cb_cast(struct command_result * (*)(struct payment *),    \
			     struct command_result * (*)(struct payment *),    \
			     step_cb),                                         \
	};

#define REGISTER_PAYMENT_CONDITION(name, condition_cb)                         \
	struct payment_condition name##_pay_cond = {                           \
	    stringify(name),                                                   \
	    typesafe_cb_cast(bool (*)(const struct payment *),                 \
			     bool (*)(const struct payment *), condition_cb),  \
	};

#endif /* LIGHTNING_PLUGINS_RENEPAY_MODS_H */
