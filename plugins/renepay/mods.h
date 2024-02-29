#ifndef LIGHTNING_PLUGINS_RENEPAY_MODS_H
#define LIGHTNING_PLUGINS_RENEPAY_MODS_H

#include "config.h"
#include <plugins/renepay/payment.h>

struct payment_modifier {
	const char *name;
	void (*post_step_cb)(struct payment *p);
};

void payment_continue(struct payment *p);

#define REGISTER_PAYMENT_MODIFIER(name, step_cb)                               \
	struct payment_modifier name##_pay_mod = {                             \
	    stringify(name),                                                   \
	    typesafe_cb_cast(void (*)(struct payment *),                       \
			     void (*)(struct payment *), step_cb),             \
	};

#define REGISTER_PAYMENT_MODIFIER_HEADER(name)                                 \
	extern struct payment_modifier name##_pay_mod;

REGISTER_PAYMENT_MODIFIER_HEADER(end);
REGISTER_PAYMENT_MODIFIER_HEADER(previous_sendpays);
REGISTER_PAYMENT_MODIFIER_HEADER(initial_sanity_checks);
REGISTER_PAYMENT_MODIFIER_HEADER(selfpay);
REGISTER_PAYMENT_MODIFIER_HEADER(getmychannels);
REGISTER_PAYMENT_MODIFIER_HEADER(refreshgossmap);
REGISTER_PAYMENT_MODIFIER_HEADER(routehints);
REGISTER_PAYMENT_MODIFIER_HEADER(compute_routes);
REGISTER_PAYMENT_MODIFIER_HEADER(send_routes);

#endif /* LIGHTNING_PLUGINS_RENEPAY_MODS_H */
