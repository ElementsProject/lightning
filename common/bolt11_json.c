#include "config.h"
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/bech32.h>
#include <common/bolt11.h>
#include <common/bolt11_json.h>
#include <common/json_stream.h>

static void json_add_fallback(struct json_stream *response,
			      const char *fieldname,
			      const u8 *fallback,
			      const struct chainparams *chain)
{
	char *addr;
	const size_t fallback_len = tal_bytelen(fallback);

	json_object_start(response, fieldname);
	if (is_p2pkh(fallback, fallback_len, NULL)) {
		json_add_string(response, "type", "P2PKH");
	} else if (is_p2sh(fallback, fallback_len, NULL)) {
		json_add_string(response, "type", "P2SH");
	} else if (is_p2wpkh(fallback, fallback_len, NULL)) {
		json_add_string(response, "type", "P2WPKH");
	} else if (is_p2wsh(fallback, fallback_len, NULL)) {
		json_add_string(response, "type", "P2WSH");
	} else if (is_p2tr(fallback, fallback_len, NULL)) {
		json_add_string(response, "type", "P2TR");
	}

	addr = encode_scriptpubkey_to_addr(tmpctx, chain, fallback);
	if (addr)
		json_add_string(response, "addr", addr);
	json_add_hex_talarr(response, "hex", fallback);
	json_object_end(response);
}

void json_add_bolt11(struct json_stream *response,
		     const struct bolt11 *b11)
{
	json_add_string(response, "currency", b11->chain->lightning_hrp);
	json_add_u64(response, "created_at", b11->timestamp);
	json_add_u64(response, "expiry", b11->expiry);
	json_add_node_id(response, "payee", &b11->receiver_id);
        if (b11->msat)
                json_add_amount_msat(response, "amount_msat", *b11->msat);
        if (b11->description)
                json_add_string(response, "description", b11->description);
        if (b11->description_hash)
                json_add_sha256(response, "description_hash",
                                b11->description_hash);
	json_add_num(response, "min_final_cltv_expiry",
		     b11->min_final_cltv_expiry);
        if (b11->payment_secret)
                json_add_secret(response, "payment_secret",
                                b11->payment_secret);
	if (b11->features)
		json_add_hex_talarr(response, "features", b11->features);
	if (b11->metadata)
		json_add_hex_talarr(response, "payment_metadata", b11->metadata);
        if (tal_count(b11->fallbacks)) {
		json_array_start(response, "fallbacks");
		for (size_t i = 0; i < tal_count(b11->fallbacks); i++)
			json_add_fallback(response, NULL,
					  b11->fallbacks[i], b11->chain);
		json_array_end(response);
        }

        if (tal_count(b11->routes)) {
                size_t i, n;

                json_array_start(response, "routes");
                for (i = 0; i < tal_count(b11->routes); i++) {
                        json_array_start(response, NULL);
                        for (n = 0; n < tal_count(b11->routes[i]); n++) {
                                json_object_start(response, NULL);
                                json_add_node_id(response, "pubkey",
						 &b11->routes[i][n].pubkey);
                                json_add_short_channel_id(response,
                                                          "short_channel_id",
                                                          b11->routes[i][n]
                                                          .short_channel_id);
                                json_add_u64(response, "fee_base_msat",
                                             b11->routes[i][n].fee_base_msat);
                                json_add_u64(response, "fee_proportional_millionths",
                                             b11->routes[i][n].fee_proportional_millionths);
                                json_add_num(response, "cltv_expiry_delta",
                                             b11->routes[i][n]
                                             .cltv_expiry_delta);
                                json_object_end(response);
                        }
                        json_array_end(response);
                }
                json_array_end(response);
        }

        if (!list_empty(&b11->extra_fields)) {
                struct bolt11_field *extra;

                json_array_start(response, "extra");
                list_for_each(&b11->extra_fields, extra, list) {
                        char *data = tal_arr(NULL, char, tal_count(extra->data)+1);
                        size_t i;

                        for (i = 0; i < tal_count(extra->data); i++)
                                data[i] = bech32_charset[extra->data[i]];
                        data[i] = '\0';
                        json_object_start(response, NULL);
                        json_add_string(response, "tag",
                                        tal_fmt(data, "%c", extra->tag));
                        json_add_string(response, "data", data);
                        tal_free(data);
                        json_object_end(response);
                }
                json_array_end(response);
        }

	json_add_sha256(response, "payment_hash", &b11->payment_hash);

	json_add_string(response, "signature",
			fmt_secp256k1_ecdsa_signature(tmpctx, &b11->sig));
}
