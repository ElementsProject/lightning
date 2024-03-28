#ifndef LIGHTNING_PLUGINS_RENEPAY_ERRORCODES_H
#define LIGHTNING_PLUGINS_RENEPAY_ERRORCODES_H

/* Common types of failures for low level functions in renepay. */
enum renepay_errorcode {
	RENEPAY_NOERROR = 0,

	RENEPAY_AMOUNT_OVERFLOW,
	RENEPAY_CHANNEL_NOT_FOUND,
	RENEPAY_BAD_CHANNEL,
	RENEPAY_BAD_ALLOCATION,
	RENEPAY_PRECONDITION_ERROR,
	RENEPAY_UNEXPECTED,
};

const char *renepay_errorcode_name(enum renepay_errorcode e);

#endif /* LIGHTNING_PLUGINS_RENEPAY_ERRORCODES_H */
