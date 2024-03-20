/* For example, in the spec tests we use the following channels:
 *
 * lightning/devtools/mkgossip 103x1x0 06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f 0000000000000000000000000000000000000000000000000000000000000002 0000000000000000000000000000000000000000000000000000000000000003 0000000000000000000000000000000000000000000000000000000000000010 0000000000000000000000000000000000000000000000000000000000000020 "" 1565587763 144 0 1000 10 "" "01080808082607" 1565587763 48 0 100 11 100000 "0151b6887026070220014c4e1cc141001e6f65fffec8a825260703c43068ceb641d7b25c3a26070441cf248da2034dfa9351a9e946d71ce86f561f50b67753fd8e385d44647bf62cdb91032607"
 *
 * lightning/devtools/mkgossip 109x1x0 06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f 0000000000000000000000000000000000000000000000000000000000000004 0000000000000000000000000000000000000000000000000000000000000005 0000000000000000000000000000000000000000000000000000000000000030 0000000000000000000000000000000000000000000000000000000000000040 "" 1565587764 144 0 1000 10 "" "" 1565587765 48 0 100 11 100000 022a03b0c0000300d000000000240020012607
 *
 * lightning/devtools/mkgossip 115x1x0 06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f 0000000000000000000000000000000000000000000000000000000000000003 0000000000000000000000000000000000000000000000000000000000000004 0000000000000000000000000000000000000000000000000000000000000050 0000000000000000000000000000000000000000000000000000000000000060 "" 1565597764 144 0 1000 10 "" "0441cf248da2034dfa9351a9e946d71ce86f561f50b67753fd8e385d44647bf62cdb91032607" 1565597765 48 0 100 11 100000 ""
 */
#include "config.h"
#include <assert.h>
#include <ccan/crc32c/crc32c.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>
#include <stdio.h>
#include <wire/peer_wire.h>

static bool verbose = false;

struct update_opts {
	u32 timestamp;
	u32 cltv_expiry_delta;
	struct amount_msat min, max;
	struct amount_msat feebase;
	u32 fee_proportional_millionths;
	u8 *addresses;
};

static int parse_options(char *argv[], struct update_opts *opts,
			 const char *desc)
{
	int argnum = 0;

	opts->timestamp = atol(argv[argnum++]);
	if (!opts->timestamp)
		errx(1, "Bad %s.timestamp", desc);
	opts->cltv_expiry_delta = atol(argv[argnum++]);
	if (!opts->cltv_expiry_delta)
		errx(1, "Bad %s.cltv_expiry_delta", desc);
	if (!parse_amount_msat(&opts->min, argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad %s.min", desc);
	argnum++;
	if (!parse_amount_msat(&opts->feebase,
			       argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad %s.feebase", desc);
	argnum++;
	opts->fee_proportional_millionths = atol(argv[argnum++]);
	if (!opts->fee_proportional_millionths)
		errx(1, "Bad %s.fee_proportional_millionths", desc);

	if (!parse_amount_msat(&opts->max,
			       argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad %s.max", desc);
	argnum++;
	opts->addresses = tal_hexdata(NULL, argv[argnum], strlen(argv[argnum]));
	if (!opts->addresses)
			errx(1, "Bad %s.addresses", desc);
	argnum++;
	return argnum;
}

static char *sig_as_hex(const secp256k1_ecdsa_signature *sig)
{
	u8 compact_sig[64];

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
						    compact_sig,
						    sig);
	return tal_hexstr(NULL, compact_sig, sizeof(compact_sig));
}

static char *sig_notation(const struct privkey *privkey,
			  struct sha256_double *hash,
			  const secp256k1_ecdsa_signature *sig)
{
	const char *pstr = tal_hexstr(NULL, privkey->secret.data,
				      sizeof(privkey->secret.data));
	const char *hstr = fmt_sha256_double(NULL, hash);

	if (verbose)
		return tal_fmt(NULL,
			       "SIG(%s:%s)\n"
			       "   -- privkey= %s\n"
			       "   -- tx_hash= %s\n"
			       "   -- computed_sig= %s",
			       pstr, hstr, pstr, hstr, sig_as_hex(sig));

	return tal_fmt(NULL, "SIG(%s:%s)", pstr, hstr);
}

/* BOLT #7:
 *
 * The checksum of a `channel_update` is the CRC32C checksum as specified in
 * [RFC3720](https://tools.ietf.org/html/rfc3720#appendix-B.4) of this
 * `channel_update` without its `signature` and `timestamp` fields.
 */
static u32 crc32_of_update(const u8 *channel_update)
{
	u32 sum;

	/* BOLT #7:
	 *
	 * 1. type: 258 (`channel_update`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`chain_hash`:`chain_hash`]
	 *    * [`short_channel_id`:`short_channel_id`]
	 *    * [`u32`:`timestamp`]
	 *...
	 */
	/* We already checked it's valid before accepting */
	assert(tal_count(channel_update) > 2 + 64 + 32 + 8 + 4);
	sum = crc32c(0, channel_update + 2 + 64, 32 + 8);
	sum = crc32c(sum, channel_update + 2 + 64 + 32 + 8 + 4,
		     tal_count(channel_update) - (64 + 2 + 32 + 8 + 4));
	return sum;
}

static void print_update(const struct bitcoin_blkid *chainhash,
			 const struct short_channel_id *scid,
			 const struct update_opts *opts,
			 bool is_lesser_key,
			 const struct privkey *privkey)
{
	/* 2 bytes msg type + 64 bytes of signature */
	const size_t channel_update_offset = 2 + 64;
	struct sha256_double hash;
	secp256k1_ecdsa_signature sig;
	u8 *cupdate;

	memset(&sig, 0, sizeof(sig));
	cupdate = towire_channel_update
			(NULL, &sig, chainhash, scid, opts->timestamp,
			 ROUTING_OPT_HTLC_MAX_MSAT,
			 is_lesser_key ? 0 : ROUTING_FLAGS_DIRECTION,
			 opts->cltv_expiry_delta,
			 opts->min,
			 opts->feebase.millisatoshis, /* Raw: devtools code */
			 opts->fee_proportional_millionths,
			 opts->max);
	sha256_double(&hash, cupdate + channel_update_offset,
		      tal_count(cupdate) - channel_update_offset);
	sign_hash(privkey, &hash, &sig);

	printf("type=channel_update\n");
	printf("   signature=%s\n", sig_notation(privkey, &hash, &sig));
	printf("   chain_hash=%s\n", tal_hexstr(NULL, chainhash, sizeof(*chainhash)));
	printf("   short_channel_id=%s\n", fmt_short_channel_id(NULL, *scid));
	printf("   timestamp=%u\n", opts->timestamp);
	printf("   message_flags=%u\n",
	       ROUTING_OPT_HTLC_MAX_MSAT);
	printf("   channel_flags=%u\n",
	       is_lesser_key ? 0 : ROUTING_FLAGS_DIRECTION);
	printf("   cltv_expiry_delta=%u\n",
	       opts->cltv_expiry_delta);
	printf("   htlc_minimum_msat=%"PRIu64"\n",
	       opts->min.millisatoshis);  /* Raw: devtools code */
	printf("   fee_base_msat=%"PRIu64"\n",
	       opts->feebase.millisatoshis);  /* Raw: devtools code */
	printf("   fee_proportional_millionths=%u\n",
	       opts->fee_proportional_millionths);
	printf("   htlc_maximum_msat=%"PRIu64"\n",
	       opts->max.millisatoshis);  /* Raw: devtools code */
	printf("# crc32c checksum: %08x\n", crc32_of_update(cupdate));
}

static void print_nannounce(const struct node_id *nodeid,
			    const struct update_opts *opts,
			    const struct privkey *privkey)
{
	/* 2 bytes msg type + 64 bytes of signature */
	const size_t node_announcement_offset = 2 + 64;
	struct sha256_double hash;
	secp256k1_ecdsa_signature sig;
	char alias[33];
	struct tlv_node_ann_tlvs *tlvs;
	u8 *nannounce;

	memset(&sig, 0, sizeof(sig));
	assert(hex_str_size(sizeof(*nodeid)) >= sizeof(alias));
	hex_encode(nodeid, hex_data_size(sizeof(alias)), alias, sizeof(alias));
	tlvs = tlv_node_ann_tlvs_new(NULL);
	nannounce = towire_node_announcement(NULL, &sig, NULL, opts->timestamp,
					     nodeid, nodeid->k, (u8 *)alias,
					     opts->addresses,
					     tlvs);
	sha256_double(&hash, nannounce + node_announcement_offset,
		      tal_count(nannounce) - node_announcement_offset);
	sign_hash(privkey, &hash, &sig);

	printf("type=node_announcement\n");
	printf("   signature=%s\n", sig_notation(privkey, &hash, &sig));
	printf("   features=%s\n", tal_hex(NULL, NULL));
	printf("   timestamp=%u\n", opts->timestamp);
	printf("   node_id=%s\n", fmt_node_id(NULL, nodeid));
	printf("   rgb_color=%s\n", tal_hexstr(NULL, nodeid->k, 3));
	printf("   alias=%s\n", tal_hexstr(NULL, alias, 32));
	printf("   addresses=%s\n", tal_hex(NULL, opts->addresses));

	if (tlvs->option_will_fund) {
		struct lease_rates *rates = tlvs->option_will_fund;
		printf("	TLV option_will_fund\n");
		printf("	lease_fee_basis=%d\n",
		       rates->lease_fee_basis);
		printf("	lease_fee_base_sat=%d\n",
		       rates->lease_fee_base_sat);
		printf("	funding_weight=%d\n",
		       rates->funding_weight);
		printf("	channel_fee_max_proportional_thousandths=%d\n",
		       rates->channel_fee_max_proportional_thousandths);
		printf("	channel_fee_max_base_msat=%d\n",
		       rates->channel_fee_max_base_msat);
	}
	tal_free(tlvs);
}

int main(int argc, char *argv[])
{
	struct privkey node_privkey[2], funding_privkey[2];
	struct pubkey node[2], bitcoin[2];
	struct node_id nodeid[2];
	int lesser_key;
	struct short_channel_id scid;
	struct bitcoin_blkid chainhash;
	secp256k1_ecdsa_signature nodesig[2], bitcoinsig[2];
	const u8 *features;
	u8 *cannounce;
	/* 2 bytes msg type + 256 bytes of signatures */
	const size_t channel_announcement_offset = 2 + 256;
	int argnum;
	struct sha256_double hash;
	struct update_opts opts[2];

	setup_locale();

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	if (argc < 8 + 7 * 2)
		errx(1, "Usage: mkgossip <scid> <chainhash> <node-privkey1> <node-privkey2> <node1-funding-privkey> <node2-funding-privkey> <features-hex> update-opts-1 update-opts-2\n"
			"Where <update-opts> is:\n"
			"   <timestamp>\n"
			"   <cltv_expiry_delta>\n"
			"   <htlc_minimum_msat>\n"
			"   <fee_base_msat>\n"
			"   <fee_proportional_millionths>\n"
			"   <htlc_maximum_msat-or-empty>\n"
			"   <hex-addrstr>");

	opt_register_noarg("-v|--verbose", opt_set_bool, &verbose,
			   "Increase verbosity");

	opt_parse(&argc, argv, opt_log_stderr_exit);

	argnum = 1;
	if (!short_channel_id_from_str(argv[argnum], strlen(argv[argnum]), &scid))
		errx(1, "Bad scid");
	argnum++;
	/* Don't do endian-reversing insanity here! */
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&chainhash, sizeof(chainhash)))
		errx(1, "Parsing chainhash");
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&node_privkey[0], sizeof(node_privkey[0])))
		errx(1, "Parsing node-privkey1");
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&node_privkey[1], sizeof(node_privkey[2])))
		errx(1, "Parsing node-privkey2");
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&funding_privkey[0], sizeof(funding_privkey[0])))
		errx(1, "Parsing funding-privkey1");
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&funding_privkey[1], sizeof(funding_privkey[2])))
		errx(1, "Parsing funding-privkey2");
	argnum++;
	features = tal_hexdata(NULL, argv[argnum], strlen(argv[argnum]));
	if (!features)
		errx(1, "Parsing hexfeatures");
	argnum++;

	argnum += parse_options(argv + argnum, &opts[0], "update-opts1");
	argnum += parse_options(argv + argnum, &opts[1], "update-opts2");

	if (!pubkey_from_privkey(&node_privkey[0], &node[0])
	    || !pubkey_from_privkey(&node_privkey[1], &node[1])
	    || !pubkey_from_privkey(&funding_privkey[0], &bitcoin[0])
	    || !pubkey_from_privkey(&funding_privkey[1], &bitcoin[1]))
		errx(1, "Bad privkeys");

	lesser_key = pubkey_idx(&node[0], &node[1]);
	node_id_from_pubkey(&nodeid[0], &node[0]);
	node_id_from_pubkey(&nodeid[1], &node[1]);

	/* First make msg with dummy sigs. */
	memset(nodesig, 0, sizeof(nodesig));
	memset(bitcoinsig, 0, sizeof(bitcoinsig));

	cannounce = towire_channel_announcement(NULL,
						&nodesig[lesser_key],
						&nodesig[!lesser_key],
						&bitcoinsig[lesser_key],
						&bitcoinsig[!lesser_key],
						features, &chainhash,
						&scid,
						&nodeid[lesser_key],
						&nodeid[!lesser_key],
						&bitcoin[lesser_key],
						&bitcoin[!lesser_key]);
	sha256_double(&hash, cannounce + channel_announcement_offset,
		      tal_count(cannounce) - channel_announcement_offset);
	sign_hash(&node_privkey[0], &hash, &nodesig[0]);
	sign_hash(&funding_privkey[0], &hash, &bitcoinsig[0]);
	sign_hash(&node_privkey[1], &hash, &nodesig[1]);
	sign_hash(&funding_privkey[1], &hash, &bitcoinsig[1]);

	printf("type=channel_announcement\n");
	printf("   node_signature_1=%s\n",
	       sig_notation(&node_privkey[lesser_key], &hash, &nodesig[lesser_key]));
	printf("   node_signature_2=%s\n",
	       sig_notation(&node_privkey[!lesser_key], &hash, &nodesig[!lesser_key]));
	printf("   bitcoin_signature_1=%s\n",
	       sig_notation(&funding_privkey[lesser_key], &hash, &bitcoinsig[lesser_key]));
	printf("   bitcoin_signature_2=%s\n",
	       sig_notation(&funding_privkey[!lesser_key], &hash, &bitcoinsig[!lesser_key]));
	printf("   features=%s\n", tal_hex(NULL, features));
	printf("   chain_hash=%s\n", tal_hexstr(NULL, &chainhash, sizeof(chainhash)));
	printf("   short_channel_id=%s\n", fmt_short_channel_id(NULL, scid));
	printf("   node_id_1=%s\n",
	       fmt_node_id(NULL, &nodeid[lesser_key]));
	printf("   node_id_2=%s\n",
	       fmt_node_id(NULL, &nodeid[!lesser_key]));
	printf("   bitcoin_key_1=%s\n",
	       fmt_pubkey(NULL, &bitcoin[lesser_key]));
	printf("   bitcoin_key_2=%s\n",
	       fmt_pubkey(NULL, &bitcoin[!lesser_key]));

	printf("\n#Node 1:\n");
	print_update(&chainhash, &scid, &opts[0], lesser_key == 0,
		     &node_privkey[0]);
	print_nannounce(&nodeid[0], &opts[0], &node_privkey[0]);

	printf("\n#Node 2:\n");
	print_update(&chainhash, &scid, &opts[1], lesser_key == 1,
		     &node_privkey[1]);

	print_nannounce(&nodeid[1], &opts[1], &node_privkey[1]);

	return 0;
}
