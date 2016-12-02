#include "failure.h"
#include "protobuf_convert.h"
#include <ccan/tal/str/str.h>

/* FIXME: Crypto! */
const u8 *failinfo_create(const tal_t *ctx,
			  const struct pubkey *id,
			  u32 error_code,
			  const char *reason)
{
	FailInfo *f = tal(ctx, FailInfo);
	u8 *arr;

	fail_info__init(f);
	f->id = pubkey_to_proto(f, id);
	f->error_code = error_code;
	if (reason)
		f->reason = tal_strdup(f, reason);
	else
		f->reason = NULL;

	arr = tal_arr(ctx, u8, fail_info__get_packed_size(f));
	fail_info__pack(f, arr);
	tal_free(f);
	return arr;
}

FailInfo *failinfo_unwrap(const tal_t *ctx, const void *data, size_t len)
{
	struct ProtobufCAllocator *prototal = make_prototal(ctx);
	FailInfo *f;

	f = fail_info__unpack(prototal, len, data);
	if (f)
		steal_from_prototal(ctx, prototal, f);
	else
		tal_free(prototal);

	return f;
}
