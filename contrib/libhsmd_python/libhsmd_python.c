#include "libhsmd_python.h"
#include <ccan/str/hex/hex.h>
#include <common/setup.h>

char *init(char *hex_hsm_secret, char *network_name) {
	const struct bip32_key_version *key_version;
	struct secret sec;
	u8 *response;
	common_setup(NULL);
	if (sodium_init() == -1) {
		fprintf(
		    stderr,
		    "Could not initialize libsodium. Maybe not enough entropy"
		    " available ?");
		return NULL;
	}

	wally_init(0);
	secp256k1_ctx = wally_get_secp_context();

	sodium_mlock(&sec, sizeof(sec));
	if (!hex_decode(hex_hsm_secret, strlen(hex_hsm_secret), sec.data,
			sizeof(sec.data))) {
		fprintf(stderr,
			"Expected hex_hsm_secret of length 64, got %zu\n",
			strlen(hex_hsm_secret));
		return NULL;
	}

	/* Look up chainparams by their name */
	chainparams = chainparams_for_network(network_name);
	if (chainparams == NULL) {
		fprintf(stderr, "Could not find chainparams for network %s\n",
			network_name);
		return NULL;
	}

	key_version = &chainparams->bip32_key_version;

	response = hsmd_init(sec, *key_version);
	sodium_munlock(&sec, sizeof(sec));

	char *res = tal_hex(NULL, response);
	tal_free(response);
	return res;
}

char *handle(long long cap, long long dbid, char *peer_id, char *hexmsg) {
	size_t res_len;
	u8 *response, *request;
	char *res;
	struct hsmd_client *client;
	struct node_id *peer = NULL;
	request = tal_hexdata(tmpctx, hexmsg, strlen(hexmsg));
	if (peer_id != NULL) {
		peer = tal(tmpctx, struct node_id);
		node_id_from_hexstr(peer_id, strlen(peer_id), peer);
		client = hsmd_client_new_peer(tmpctx, cap, dbid, peer, NULL);
	} else {
		client = hsmd_client_new_main(tmpctx, cap, NULL);
	}
	response = hsmd_handle_client_message(tmpctx, client, request);
	if (response == NULL) {
		clean_tmpctx();
		return NULL;
	}

	res_len = hex_str_size(tal_bytelen(response));
	res = malloc(res_len);
	hex_encode(response, tal_bytelen(response), res, res_len);

	clean_tmpctx();
	return res;
}
