#include "config.h"
#include <common/json_stream.h>
#include <plugins/bkpr/onchain_fee.h>


void json_add_onchain_fee(struct json_stream *out,
			  struct onchain_fee *fee)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", fee->acct_name);
	json_add_string(out, "type", "onchain_fee");
	json_add_string(out, "tag", "onchain_fee");
	json_add_amount_msat_only(out, "credit_msat", fee->credit);
	json_add_amount_msat_only(out, "debit_msat", fee->debit);
	json_add_string(out, "currency", fee->currency);
	json_add_u64(out, "timestamp", fee->timestamp);
	json_add_txid(out, "txid", &fee->txid);
	json_object_end(out);
}

