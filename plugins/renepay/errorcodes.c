#include "config.h"
#include <ccan/tal/str/str.h>
#include <plugins/renepay/errorcodes.h>
#include <stdio.h>

const char *renepay_errorcode_name(enum renepay_errorcode e)
{
	static char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

	switch (e) {
	case RENEPAY_NOERROR:
		return "RENEPAY_NOERROR";
	case RENEPAY_AMOUNT_OVERFLOW:
		return "RENEPAY_AMOUNT_OVERFLOW";
	case RENEPAY_CHANNEL_NOT_FOUND:
		return "RENEPAY_CHANNEL_NOT_FOUND";
	case RENEPAY_BAD_CHANNEL:
		return "RENEPAY_BAD_CHANNEL";
	case RENEPAY_BAD_ALLOCATION:
		return "RENEPAY_BAD_ALLOCATION";
	case RENEPAY_PRECONDITION_ERROR:
		return "RENEPAY_PRECONDITION_ERROR";
	case RENEPAY_UNEXPECTED:
		return "RENEPAY_UNEXPECTED";
	}

	snprintf(invalidbuf, sizeof(invalidbuf), "INVALID %i", e);
	return invalidbuf;
}
