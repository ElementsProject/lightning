/* Test of https://github.com/ElementsProject/lightning/issues/3703:
 *
 * > 2020-05-04T05:17:36.958Z **BROKEN** gossipd: peer 0254ff808f53b2f8c45e74b70430f336c6c76ba2f4af289f48d6086ae6e60462d3 invalid local_channel_announcement 0db201b3010011effc9ed10fceccfae5f9e3fef20d983b06eed030e968fd8d1e6c5905e18f9f2df6a43f00d7c0ddf52e0467ab1e32394051b72ea6343fb008a4117c265f3d7b732bab7df4ee404ac926aef6610f4eb33e31baabfd9afdbf897c8a80057efa1468362b4d2cc0a5482013e1058c8205717f85c3bc82c3ea89f17cfeac21e2cb2ac65b429f79b24fbd51094bee5e080d4c7cfc28a584e279075643054a48b2972f0b72becfd57e03297bf0102b09329982e0ac839dc120959c07456431d3c8fd1430ffe2cc2710e9600e602779c9cf5f91e95874ef4bcf9f0bdda2ce2be97bba562848a2717acdb8dec30bd5073f2f853776cc98f0b6cddc2dcfb57aa69fa7c43400030800006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000009984d00063a00010254ff808f53b2f8c45e74b70430f336c6c76ba2f4af289f48d6086ae6e60462d303baa70886d9200af0ffbd3f9e18d96008331c858456b16e3a9b41e735c6208fef03c8731bbac446b7d11b7f5a1861c7d2c87ccf429780c74463de3428dceeb73ad702b3e55c7a1a6cdf17a83a801f7f8f698e4980323e2584f27a643a1b0519ebf8c7 (001100000000000000000000000000000000000000000000000000000000000000000463426164206e6f64655f7369676e61747572655f3120333034343032323031316566666339656431306663656363666165356639653366656632306439383362303665656430333065393638666438643165366335393035653138663966303232303264663661343366303064376330646466353265303436376162316533323339343035316237326561363334336662303038613431313763323635663364376220686173682062623932623866343562343865363561643266326366666632323432666139323162346366343666373039613337326361373738383533376538396439646531206f6e206e6f64655f616e6e6f756e63656d656e7420303130303131656666633965643130666365636366616535663965336665663230643938336230366565643033306539363866643864316536633539303565313866396632646636613433663030643763306464663532653034363761623165333233393430353162373265613633343366623030386134313137633236356633643762373332626162376466346565343034616339323661656636363130663465623333653331626161626664396166646266383937633861383030353765666131343638333632623464326363306135343832303133653130353863383230353731376638356333626338326333656138396631376366656163323165326362326163363562343239663739623234666264353130393462656535653038306434633763666332386135383465323739303735363433303534613438623239373266306237326265636664353765303332393762663031303262303933323939383265306163383339646331323039353963303734353634333164336338666431343330666665326363323731306539363030653630323737396339636635663931653935383734656634626366396630626464613263653262653937626261353632383438613237313761636462386465633330626435303733663266383533373736636339386630623663646463326463666235376161363966613763343334303030333038303030303666653238633061623666316233373263316136613234366165363366373466393331653833363565313561303839633638643631393030303030303030303030393938346430303036336130303031303235346666383038663533623266386334356537346237303433306633333663366337366261326634616632383966343864363038366165366536303436326433303362616137303838366439323030616630666662643366396531386439363030383333316338353834353662313665336139623431653733356336323038666566303363383733316262616334343662376431316237663561313836316337643263383763636634323937383063373434363364653334323864636565623733616437303262336535356337613161366364663137613833613830316637663866363938653439383033323365323538346632376136343361316230353139656266386337)
 *
 * OK, so your peer is 0254ff808f53b2f8c45e74b70430f336c6c76ba2f4af289f48d6086ae6e60462d3, and we consider it to be a bad channel_announcement signature (it says "node_announcement" in the message below, but that's a typo!):

```
Bad node_signature_1 3044022011effc9ed10fceccfae5f9e3fef20d983b06eed030e968fd8d1e6c5905e18f9f02202df6a43f00d7c0ddf52e0467ab1e32394051b72ea6343fb008a4117c265f3d7b hash bb92b8f45b48e65ad2f2cfff2242fa921b4cf46f709a372ca7788537e89d9de1 on node_announcement 010011effc9ed10fceccfae5f9e3fef20d983b06eed030e968fd8d1e6c5905e18f9f2df6a43f00d7c0ddf52e0467ab1e32394051b72ea6343fb008a4117c265f3d7b732bab7df4ee404ac926aef6610f4eb33e31baabfd9afdbf897c8a80057efa1468362b4d2cc0a5482013e1058c8205717f85c3bc82c3ea89f17cfeac21e2cb2ac65b429f79b24fbd51094bee5e080d4c7cfc28a584e279075643054a48b2972f0b72becfd57e03297bf0102b09329982e0ac839dc120959c07456431d3c8fd1430ffe2cc2710e9600e602779c9cf5f91e95874ef4bcf9f0bdda2ce2be97bba562848a2717acdb8dec30bd5073f2f853776cc98f0b6cddc2dcfb57aa69fa7c43400030800006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000009984d00063a00010254ff808f53b2f8c45e74b70430f336c6c76ba2f4af289f48d6086ae6e60462d303baa70886d9200af0ffbd3f9e18d96008331c858456b16e3a9b41e735c6208fef03c8731bbac446b7d11b7f5a1861c7d2c87ccf429780c74463de3428dceeb73ad702b3e55c7a1a6cdf17a83a801f7f8f698e4980323e2584f27a643a1b0519ebf8c7
```

Here's what we think the channel_announcement should look like:
```
WIRE_CHANNEL_ANNOUNCEMENT:
node_signature_1=3044022011effc9ed10fceccfae5f9e3fef20d983b06eed030e968fd8d1e6c5905e18f9f02202df6a43f00d7c0ddf52e0467ab1e32394051b72ea6343fb008a4117c265f3d7b
node_signature_2=30440220732bab7df4ee404ac926aef6610f4eb33e31baabfd9afdbf897c8a80057efa14022068362b4d2cc0a5482013e1058c8205717f85c3bc82c3ea89f17cfeac21e2cb2a
bitcoin_signature_1=3045022100c65b429f79b24fbd51094bee5e080d4c7cfc28a584e279075643054a48b2972f02200b72becfd57e03297bf0102b09329982e0ac839dc120959c07456431d3c8fd14
bitcoin_signature_2=3044022030ffe2cc2710e9600e602779c9cf5f91e95874ef4bcf9f0bdda2ce2be97bba5602202848a2717acdb8dec30bd5073f2f853776cc98f0b6cddc2dcfb57aa69fa7c434
features=[080000]
chain_hash=000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
short_channel_id=628813x1594x1
node_id_1=0254ff808f53b2f8c45e74b70430f336c6c76ba2f4af289f48d6086ae6e60462d3
node_id_2=03baa70886d9200af0ffbd3f9e18d96008331c858456b16e3a9b41e735c6208fef
bitcoin_key_1=03c8731bbac446b7d11b7f5a1861c7d2c87ccf429780c74463de3428dceeb73ad7
bitcoin_key_2=02b3e55c7a1a6cdf17a83a801f7f8f698e4980323e2584f27a643a1b0519ebf8c7
```

In particular, we set feature bit 19.  The spec says we should set feature bit 18 (which is clearly wrong!).
*/

#include "config.h"
#include "../common/wire_error.c"
#include "../routing.c"
#include <common/blinding.h>
#include <common/channel_type.h>
#include <common/ecdh.h>
#include <common/json_stream.h>
#include <common/onionreply.h>
#include <common/setup.h>
#include <stdio.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for blinding_hash_e_and_ss */
void blinding_hash_e_and_ss(const struct pubkey *e UNNEEDED,
			    const struct secret *ss UNNEEDED,
			    struct sha256 *sha UNNEEDED)
{ fprintf(stderr, "blinding_hash_e_and_ss called!\n"); abort(); }
/* Generated stub for blinding_next_privkey */
bool blinding_next_privkey(const struct privkey *e UNNEEDED,
			   const struct sha256 *h UNNEEDED,
			   struct privkey *next UNNEEDED)
{ fprintf(stderr, "blinding_next_privkey called!\n"); abort(); }
/* Generated stub for blinding_next_pubkey */
bool blinding_next_pubkey(const struct pubkey *pk UNNEEDED,
			  const struct sha256 *h UNNEEDED,
			  struct pubkey *next UNNEEDED)
{ fprintf(stderr, "blinding_next_pubkey called!\n"); abort(); }
/* Generated stub for daemon_conn_send */
void daemon_conn_send(struct daemon_conn *dc UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "daemon_conn_send called!\n"); abort(); }
/* Generated stub for get_cupdate_parts */
void get_cupdate_parts(const u8 *channel_update UNNEEDED,
		       const u8 *parts[2] UNNEEDED,
		       size_t sizes[2])
{ fprintf(stderr, "get_cupdate_parts called!\n"); abort(); }
/* Generated stub for gossip_store_add */
u64 gossip_store_add(struct gossip_store *gs UNNEEDED, const u8 *gossip_msg UNNEEDED,
		     u32 timestamp UNNEEDED, bool zombie UNNEEDED, bool spam UNNEEDED, bool dying UNNEEDED,
		     const u8 *addendum UNNEEDED)
{ fprintf(stderr, "gossip_store_add called!\n"); abort(); }
/* Generated stub for gossip_store_delete */
void gossip_store_delete(struct gossip_store *gs UNNEEDED,
			 struct broadcastable *bcast UNNEEDED,
			 int type UNNEEDED)
{ fprintf(stderr, "gossip_store_delete called!\n"); abort(); }
/* Generated stub for gossip_store_get */
const u8 *gossip_store_get(const tal_t *ctx UNNEEDED,
			   struct gossip_store *gs UNNEEDED,
			   u64 offset UNNEEDED)
{ fprintf(stderr, "gossip_store_get called!\n"); abort(); }
/* Generated stub for gossip_store_mark_channel_deleted */
void gossip_store_mark_channel_deleted(struct gossip_store *gs UNNEEDED,
				       const struct short_channel_id *scid UNNEEDED)
{ fprintf(stderr, "gossip_store_mark_channel_deleted called!\n"); abort(); }
/* Generated stub for gossip_store_mark_dying */
void gossip_store_mark_dying(struct gossip_store *gs UNNEEDED,
			     const struct broadcastable *bcast UNNEEDED,
			     int type UNNEEDED)
{ fprintf(stderr, "gossip_store_mark_dying called!\n"); abort(); }
/* Generated stub for gossip_store_new */
struct gossip_store *gossip_store_new(struct routing_state *rstate UNNEEDED)
{ fprintf(stderr, "gossip_store_new called!\n"); abort(); }
/* Generated stub for in_txout_failures */
bool in_txout_failures(struct txout_failures *txf UNNEEDED,
		       const struct short_channel_id scid UNNEEDED)
{ fprintf(stderr, "in_txout_failures called!\n"); abort(); }
/* Generated stub for memleak_add_helper_ */
void memleak_add_helper_(const tal_t *p UNNEEDED, void (*cb)(struct htable *memtable UNNEEDED,
						    const tal_t *)){ }
/* Generated stub for memleak_scan_htable */
void memleak_scan_htable(struct htable *memtable UNNEEDED, const struct htable *ht UNNEEDED)
{ fprintf(stderr, "memleak_scan_htable called!\n"); abort(); }
/* Generated stub for memleak_scan_intmap_ */
void memleak_scan_intmap_(struct htable *memtable UNNEEDED, const struct intmap *m UNNEEDED)
{ fprintf(stderr, "memleak_scan_intmap_ called!\n"); abort(); }
/* Generated stub for notleak_ */
void *notleak_(void *ptr UNNEEDED, bool plus_children UNNEEDED)
{ fprintf(stderr, "notleak_ called!\n"); abort(); }
/* Generated stub for peer_supplied_good_gossip */
void peer_supplied_good_gossip(struct daemon *daemon UNNEEDED,
			       const struct node_id *source_peer UNNEEDED,
			       size_t amount UNNEEDED)
{ fprintf(stderr, "peer_supplied_good_gossip called!\n"); abort(); }
/* Generated stub for status_fmt */
void status_fmt(enum log_level level UNNEEDED,
		const struct node_id *peer UNNEEDED,
		const char *fmt UNNEEDED, ...)

{ fprintf(stderr, "status_fmt called!\n"); abort(); }
/* Generated stub for towire_gossipd_remote_channel_update */
u8 *towire_gossipd_remote_channel_update(const tal_t *ctx UNNEEDED, const struct node_id *source_node UNNEEDED, const struct peer_update *peer_update UNNEEDED)
{ fprintf(stderr, "towire_gossipd_remote_channel_update called!\n"); abort(); }
/* Generated stub for txout_failures_add */
void txout_failures_add(struct txout_failures *txf UNNEEDED,
			const struct short_channel_id scid UNNEEDED)
{ fprintf(stderr, "txout_failures_add called!\n"); abort(); }
/* Generated stub for txout_failures_new */
struct txout_failures *txout_failures_new(const tal_t *ctx UNNEEDED, struct daemon *daemon UNNEEDED)
{ fprintf(stderr, "txout_failures_new called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

int main(int argc, char *argv[])
{
	struct bitcoin_blkid chain_hash;
	u8 *features, *err;
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	struct short_channel_id short_channel_id;
	struct node_id node_id_1, node_id_2;
	struct pubkey bitcoin_key_1, bitcoin_key_2;
	const u8 *cannounce;

	common_setup(argv[0]);

	cannounce = tal_hexdata(tmpctx, "010011effc9ed10fceccfae5f9e3fef20d983b06eed030e968fd8d1e6c5905e18f9f2df6a43f00d7c0ddf52e0467ab1e32394051b72ea6343fb008a4117c265f3d7b732bab7df4ee404ac926aef6610f4eb33e31baabfd9afdbf897c8a80057efa1468362b4d2cc0a5482013e1058c8205717f85c3bc82c3ea89f17cfeac21e2cb2ac65b429f79b24fbd51094bee5e080d4c7cfc28a584e279075643054a48b2972f0b72becfd57e03297bf0102b09329982e0ac839dc120959c07456431d3c8fd1430ffe2cc2710e9600e602779c9cf5f91e95874ef4bcf9f0bdda2ce2be97bba562848a2717acdb8dec30bd5073f2f853776cc98f0b6cddc2dcfb57aa69fa7c43400030800006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000009984d00063a00010254ff808f53b2f8c45e74b70430f336c6c76ba2f4af289f48d6086ae6e60462d303baa70886d9200af0ffbd3f9e18d96008331c858456b16e3a9b41e735c6208fef03c8731bbac446b7d11b7f5a1861c7d2c87ccf429780c74463de3428dceeb73ad702b3e55c7a1a6cdf17a83a801f7f8f698e4980323e2584f27a643a1b0519ebf8c7", strlen("010011effc9ed10fceccfae5f9e3fef20d983b06eed030e968fd8d1e6c5905e18f9f2df6a43f00d7c0ddf52e0467ab1e32394051b72ea6343fb008a4117c265f3d7b732bab7df4ee404ac926aef6610f4eb33e31baabfd9afdbf897c8a80057efa1468362b4d2cc0a5482013e1058c8205717f85c3bc82c3ea89f17cfeac21e2cb2ac65b429f79b24fbd51094bee5e080d4c7cfc28a584e279075643054a48b2972f0b72becfd57e03297bf0102b09329982e0ac839dc120959c07456431d3c8fd1430ffe2cc2710e9600e602779c9cf5f91e95874ef4bcf9f0bdda2ce2be97bba562848a2717acdb8dec30bd5073f2f853776cc98f0b6cddc2dcfb57aa69fa7c43400030800006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000009984d00063a00010254ff808f53b2f8c45e74b70430f336c6c76ba2f4af289f48d6086ae6e60462d303baa70886d9200af0ffbd3f9e18d96008331c858456b16e3a9b41e735c6208fef03c8731bbac446b7d11b7f5a1861c7d2c87ccf429780c74463de3428dceeb73ad702b3e55c7a1a6cdf17a83a801f7f8f698e4980323e2584f27a643a1b0519ebf8c7"));
	if (!fromwire_channel_announcement(cannounce, cannounce,
					   &node_signature_1,
					   &node_signature_2,
					   &bitcoin_signature_1,
					   &bitcoin_signature_2,
					   &features,
					   &chain_hash,
					   &short_channel_id,
					   &node_id_1,
					   &node_id_2,
					   &bitcoin_key_1,
					   &bitcoin_key_2))
		abort();

	err = check_channel_announcement(cannounce,
					 &node_id_1, &node_id_2,
					 &bitcoin_key_1, &bitcoin_key_2,
					 &node_signature_1, &node_signature_2,
					 &bitcoin_signature_1,
					 &bitcoin_signature_2,
					 cannounce);
	assert(err);
	assert(memmem(err, tal_bytelen(err),
		      "Bad node_signature_1", strlen("Bad node_signature_1")));

	/* Turns out they didn't include the feature bit at all. */
	cannounce = towire_channel_announcement(tmpctx,
						&node_signature_1,
						&node_signature_2,
						&bitcoin_signature_1,
						&bitcoin_signature_2,
						NULL,
						&chain_hash,
						&short_channel_id,
						&node_id_1,
						&node_id_2,
						&bitcoin_key_1,
						&bitcoin_key_2);
	err = check_channel_announcement(cannounce,
					 &node_id_1, &node_id_2,
					 &bitcoin_key_1, &bitcoin_key_2,
					 &node_signature_1, &node_signature_2,
					 &bitcoin_signature_1,
					 &bitcoin_signature_2,
					 cannounce);
	assert(err);
	assert(memmem(err, tal_bytelen(err),
		      "Bad node_signature_2", strlen("Bad node_signature_2")));

	common_shutdown();
	return 0;
}
