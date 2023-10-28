/* Forwarding APIs */
#ifndef LIGHTNING_LIGHTNINGD_FORWARDS_H
#define LIGHTNING_LIGHTNINGD_FORWARDS_H
#include "config.h"
#include <wire/onion_wire.h>

struct json_stream;
struct lightningd;
struct sha256;

/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
enum forward_style {
	FORWARD_STYLE_LEGACY = 0,
	FORWARD_STYLE_TLV = 1,
	FORWARD_STYLE_UNKNOWN = 2, /* Not actually in db, safe to renumber! */
};

/**
 * Possible states for forwards
 *
 */
/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
enum forward_status {
	FORWARD_OFFERED = 0,
	FORWARD_SETTLED = 1,
	FORWARD_FAILED = 2,
	FORWARD_LOCAL_FAILED = 3,
	/* Special status used to express that we don't care in
	 * queries */
	FORWARD_ANY = 255

};

struct forwarding {
	u64 created_index;
	/* zero means never updated */
	u64 updated_index;
	/* channel_out is all-zero if unknown. */
	struct short_channel_id channel_in, channel_out;
	/* htlc_id_out is NULL if unknown. */
	u64 htlc_id_in, *htlc_id_out;
	struct amount_msat msat_in, msat_out, fee;
	enum forward_style forward_style;
	enum forward_status status;
	enum onion_wire failcode;
	struct timeabs received_time;
	/* May not be present if the HTLC was not resolved yet. */
	struct timeabs *resolved_time;
};

/* This json function will be used as the serialize method for
 * forward_event_notification_gen and be used in
 * `listforwardings_add_forwardings()`. */
void json_add_forwarding_object(struct json_stream *response,
				const char *fieldname,
				const struct forwarding *cur,
				const struct sha256 *payment_hash);

static inline const char* forward_status_name(enum forward_status status)
{
	switch(status) {
	case FORWARD_OFFERED:
		return "offered";
	case FORWARD_SETTLED:
		return "settled";
	case FORWARD_FAILED:
		return "failed";
	case FORWARD_LOCAL_FAILED:
		return "local_failed";
	case FORWARD_ANY:
		return "any";
	}
	abort();
}

bool string_to_forward_status(const char *status_str, size_t len,
			      enum forward_status *status);

static inline const char *forward_style_name(enum forward_style style)
{
	switch (style) {
	case FORWARD_STYLE_UNKNOWN:
		return "UNKNOWN";
	case FORWARD_STYLE_TLV:
		return "tlv";
	case FORWARD_STYLE_LEGACY:
		return "legacy";
	}
	abort();
}

/* wait() hooks in here */
void forward_index_deleted(struct lightningd *ld,
			   enum forward_status status,
			   struct short_channel_id in_channel,
			   const struct amount_msat *in_amount,
			   const struct short_channel_id *out_channel);
u64 forward_index_created(struct lightningd *ld,
			  enum forward_status status,
			  struct short_channel_id in_channel,
			  struct amount_msat in_amount,
			  const struct short_channel_id *out_channel);
u64 forward_index_update_status(struct lightningd *ld,
				enum forward_status status,
				struct short_channel_id in_channel,
				struct amount_msat in_amount,
				const struct short_channel_id *out_channel);
#endif /* LIGHTNING_LIGHTNINGD_FORWARDS_H */
