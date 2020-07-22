#include "contrib/remote_hsmd/dump.hpp"

extern "C" {
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/signature.h>
#include <bitcoin/tx.h>
#include <common/derive_basepoints.h>
#include <common/node_id.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/utxo.h>
}
#include <iostream>
#include <sstream>
extern "C" {
#include <wally_bip32.h>
}


using std::ostringstream;
using std::string;

bool pubkey_is_compressed(const unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN]) {
    return pubkey[0] == 0x02 || pubkey[0] == 0x03;
}

/* type_to_string has issues in the C++ environment, use this to
   dump binary data as hex instead. */
string dump_hex(const void *vptr, size_t sz)
{
	static const char hex[] = "0123456789abcdef";
	ostringstream ostrm;
	ostrm << '"';
	uint8_t const * ptr = (uint8_t const *) vptr;
	for (size_t ii = 0; ii < sz; ++ii) {
		ostrm << hex[(*ptr) >> 4]
		      << hex[(*ptr) & 0xf];
		++ptr;
	}
	ostrm << '"';
	return ostrm.str();
}

string dump_bitcoin_txid(const struct bitcoin_txid *txid)
{
	return dump_hex(txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
}

string dump_bitcoin_signature(const struct bitcoin_signature *sp)
{
	ostringstream ostrm;
	ostrm << "{ "
	      << "\"sighash_type\":" << int(sp->sighash_type)
	      << ", \"s\":"
	      << '"' << dump_secp256k1_ecdsa_signature(&sp->s) << '"'
	      << " }";
	return ostrm.str();
}

string dump_secp256k1_ecdsa_signature(const secp256k1_ecdsa_signature *sp)
{
	return dump_hex(sp->data, sizeof(sp->data));
}

string dump_secp256k1_ecdsa_recoverable_signature(
	const secp256k1_ecdsa_recoverable_signature *sp)
{
	return dump_hex(sp->data, sizeof(sp->data));
}

string dump_secret(const struct secret *sp)
{
	return dump_hex(sp->data, sizeof(sp->data));
}

string dump_node_id(const struct node_id *pp)
{
	return dump_hex(pp->k, sizeof(pp->k));
}

string dump_pubkey(const struct pubkey *kp)
{
	return dump_hex(kp->pubkey.data, sizeof(kp->pubkey.data));
}

string dump_ext_pubkey(const struct ext_key *xp)
{
	char *out;
	int rv = bip32_key_to_base58(xp, BIP32_FLAG_KEY_PUBLIC, &out);
	assert(rv == WALLY_OK);
	string retval(out);
	wally_free_string(out);
	return retval;
}

string dump_witnesses(const u8 ***wp)
{
	ostringstream ostrm;
 	ostrm << "[";
	for (size_t input_ndx = 0; input_ndx < tal_count(wp); ++input_ndx) {
		if (input_ndx != 0)
			ostrm << ", ";
		ostrm << "[";
		u8 const *sig = wp[input_ndx][0];
		ostrm << dump_hex(sig, tal_count(sig));
		ostrm << ", ";
		u8 const *pubkey = wp[input_ndx][1];
		ostrm << dump_hex(pubkey, tal_count(pubkey));
		ostrm << "]";
	}
 	ostrm << "]";
	return ostrm.str();
}

string dump_basepoints(const struct basepoints *bp)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"revocation\":" << dump_pubkey(&bp->revocation);
	ostrm << ", \"payment\":" << dump_pubkey(&bp->payment);
	ostrm << ", \"htlc\":" << dump_pubkey(&bp->htlc);
	ostrm << ", \"delayed_payment\":" << dump_pubkey(&bp->delayed_payment);
	ostrm << " }";
	return ostrm.str();
}

string dump_unilateral_close_info(const struct unilateral_close_info *ip)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"channel_id\":" << ip->channel_id;
	ostrm << ", \"peer_id\":" << dump_node_id(&ip->peer_id);
	ostrm << ", \"commitment_point\":" <<
		(ip->commitment_point ? dump_pubkey(ip->commitment_point) :
		 "\"<none>\"");
	ostrm << " }";
	return ostrm.str();
}

string dump_utxo(const struct utxo *in)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"txid\":" << dump_bitcoin_txid(&in->txid);
	ostrm << ", \"outnum\":" << in->outnum;
	ostrm << ", \"amount\":" << in->amount.satoshis;
	ostrm << ", \"keyindex\":" << in->keyindex;
	ostrm << ", \"is_p2sh\":" << in->is_p2sh;
	ostrm << ", \"close_info\":" <<
		(in->close_info ?
		 dump_unilateral_close_info(in->close_info) :
		 "\"<none>\"");
	ostrm << " }";
	return ostrm.str();
}

string dump_utxos(const struct utxo **utxos)
{
	ostringstream ostrm;
	ostrm << "[";
	for (size_t ii = 0; ii < tal_count(utxos); ii++) {
		if (ii != 0)
			ostrm << ",";
		ostrm << dump_utxo(utxos[ii]);
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_bitcoin_tx_output(const struct bitcoin_tx_output *op)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"amount\":" << op->amount.satoshis;
	ostrm << ", \"script\":" <<
	   (op->script ? dump_hex(op->script, tal_count(op->script)) : "\"<none>\"");
	ostrm << " }";
	return ostrm.str();
}

string dump_bitcoin_tx_outputs(const struct bitcoin_tx_output **outputs)
{
	ostringstream ostrm;
	ostrm << "[";
	for (size_t ii = 0; ii < tal_count(outputs); ii++) {
		if (ii != 0)
			ostrm << ",";
		ostrm << dump_bitcoin_tx_output(outputs[ii]);
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_tx_witness_stack(const struct wally_tx_witness_stack *sp)
{
	if (sp == NULL)
		return "[]";
	ostringstream ostrm;
	ostrm << "[";
	for (size_t ii = 0; ii < sp->num_items; ii++) {
		if (ii != 0)
			ostrm << ",";
		ostrm << dump_hex(sp->items[ii].witness,
				  sp->items[ii].witness_len);
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_keypath_item(const struct wally_keypath_item *ip)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"pubkey\":" << dump_hex(
		ip->pubkey, pubkey_is_compressed(ip->pubkey) ?
		EC_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
	ostrm << ", \"origin\":{ ";
	ostrm << " \"fingerprint\":" << dump_hex(ip->origin.fingerprint,
					      sizeof(ip->origin.fingerprint));
	ostrm << ", \"path\":[ ";
	for (size_t ii = 0; ii < ip->origin.path_len; ++ii) {
		if (ii != 0)
			ostrm << ",";
		ostrm << ip->origin.path[ii];
	}
	ostrm << " ]";
	ostrm << " }";
	ostrm << " }";
	return ostrm.str();
}

string dump_wally_keypath_map(const struct wally_keypath_map *mp)
{
	ostringstream ostrm;
	ostrm << "[";
	if (mp) {
		for (size_t ii = 0; ii < mp->num_items; ii++) {
			if (ii != 0)
				ostrm << ",";
			ostrm << dump_wally_keypath_item(&mp->items[ii]);
		}
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_partial_sigs_item(const struct wally_partial_sigs_item *ip)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"pubkey\":" << dump_hex(
		ip->pubkey, pubkey_is_compressed(ip->pubkey) ?
		EC_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
	ostrm << ", \"sig\":" << dump_hex(ip->sig, ip->sig_len);
	ostrm << " }";
	return ostrm.str();
}

string dump_wally_partial_sigs_map(const struct wally_partial_sigs_map *mp)
{
	ostringstream ostrm;
	ostrm << "[";
	if (mp) {
		for (size_t ii = 0; ii < mp->num_items; ii++) {
			if (ii != 0)
				ostrm << ",";
			ostrm << dump_wally_partial_sigs_item(&mp->items[ii]);
		}
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_unknowns_item(const struct wally_unknowns_item *ip)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"key\":" << dump_hex(ip->key, ip->key_len);
	ostrm << ", \"value\":" << dump_hex(ip->value, ip->value_len);
	ostrm << " }";
	return ostrm.str();
}

string dump_wally_unknowns_map(const struct wally_unknowns_map *mp)
{
	ostringstream ostrm;
	ostrm << "[";
	if (mp) {
		for (size_t ii = 0; ii < mp->num_items; ii++) {
			if (ii != 0)
				ostrm << ",";
			ostrm << dump_wally_unknowns_item(&mp->items[ii]);
		}
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_tx_input(const struct wally_tx_input *in)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"txhash\":" << dump_hex(in->txhash, sizeof(in->txhash));
	ostrm << ", \"index\":" << in->index;
	ostrm << ", \"sequence\":" << in->sequence;
	ostrm << ", \"script\":" <<
		(in->script_len ? dump_hex(in->script, in->script_len) :
		 "\"<none>\"");
	ostrm << ", \"witness\":" <<
		(in->witness ? dump_wally_tx_witness_stack(in->witness) :
		 "\"<none>\"");
	ostrm << ", \"features\":" << int(in->features);
	ostrm << " }";
	return ostrm.str();
}

string dump_wally_tx_inputs(const struct wally_tx_input *inputs,
			    size_t num_inputs)
{
	ostringstream ostrm;
	ostrm << "[";
	for (size_t ii = 0; ii < num_inputs; ii++) {
		if (ii != 0)
			ostrm << ",";
		ostrm << dump_wally_tx_input(&inputs[ii]);
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_tx_output(const struct wally_tx_output *out)
{
	if (out == NULL)
		return "{}";
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"satoshi\":" << out->satoshi;
	ostrm << ", \"script\":" <<
		(out->script_len ? dump_hex(out->script, out->script_len) :
		 "\"<none>\"");
	ostrm << ", \"features\":" << int(out->features);
	ostrm << " }";
	return ostrm.str();
}

string dump_wally_tx_outputs(const struct wally_tx_output *outputs,
			    size_t num_outputs)
{
	ostringstream ostrm;
	ostrm << "[";
	for (size_t ii = 0; ii < num_outputs; ii++) {
		if (ii != 0)
			ostrm << ",";
		ostrm << dump_wally_tx_output(&outputs[ii]);
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_tx(const struct wally_tx *wtx)
{
	if (wtx == NULL)
		return "{}";
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"version\":" << wtx->version;
	ostrm << ", \"locktime\":" << wtx->locktime;
	ostrm << ", \"inputs\":" <<
		dump_wally_tx_inputs(wtx->inputs, wtx->num_inputs);
	ostrm << ", \"inputs_allocation_len\":" << wtx->inputs_allocation_len;
	ostrm << ", \"outputs\":" <<
		dump_wally_tx_outputs(wtx->outputs, wtx->num_outputs);
	ostrm << ", \"outputs_allocation_len\":" << wtx->outputs_allocation_len;
	ostrm << " }";
	return ostrm.str();
}

string dump_wally_psbt_input(const struct wally_psbt_input *in)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"non_witness_utxo\":" << dump_wally_tx(in->non_witness_utxo);
	ostrm << ", \"witness_utxo\":" << dump_wally_tx_output(in->witness_utxo);
	ostrm << ", \"redeem_script\":" << dump_hex(in->redeem_script,
						    in->redeem_script_len);
	ostrm << ", \"witness_script\":" << dump_hex(in->witness_script,
						     in->witness_script_len);
	ostrm << ", \"final_script_sig\":" << dump_hex(in->final_script_sig,
						       in->final_script_sig_len);
	ostrm << ", \"final_witness\":"
	      << dump_wally_tx_witness_stack(in->final_witness);
	ostrm << ", \"keypaths\":" << dump_wally_keypath_map(in->keypaths);
	ostrm << ", \"partial_sigs\":"
	      << dump_wally_partial_sigs_map(in->partial_sigs);
	ostrm << ", \"unknowns\":" << dump_wally_unknowns_map(in->unknowns);
	ostrm << ", \"sighash_type\":" << in->sighash_type;
	ostrm << " }";
	return ostrm.str();
}

string dump_wally_psbt_inputs(const struct wally_psbt_input *inputs,
			      size_t num_inputs)
{
	ostringstream ostrm;
	ostrm << "[";
	for (size_t ii = 0; ii < num_inputs; ii++) {
		if (ii != 0)
			ostrm << ",";
		ostrm << dump_wally_psbt_input(&inputs[ii]);
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_psbt_output(const struct wally_psbt_output *out)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"redeem_script\":" << dump_hex(out->redeem_script,
						  out->redeem_script_len);
	ostrm << ", \"witness_script\":" << dump_hex(out->witness_script,
						     out->witness_script_len);
	ostrm << ", \"keypaths\":" << dump_wally_keypath_map(out->keypaths);
	ostrm << ", \"unknowns\":" << dump_wally_unknowns_map(out->unknowns);
	ostrm << " }";
	return ostrm.str();

}

string dump_wally_psbt_outputs(const struct wally_psbt_output *outputs,
			      size_t num_outputs)
{
	ostringstream ostrm;
	ostrm << "[";
	for (size_t ii = 0; ii < num_outputs; ii++) {
		if (ii != 0)
			ostrm << ",";
		ostrm << dump_wally_psbt_output(&outputs[ii]);
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_psbt(const struct wally_psbt *psbt)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"magic\":" << dump_hex(psbt->magic, sizeof(psbt->magic));
	ostrm << ", \"tx\":" << dump_wally_tx(psbt->tx);
	ostrm << ", \"inputs\":"
	      << dump_wally_psbt_inputs(psbt->inputs, psbt->num_inputs);
	ostrm << ", \"outputs\":"
	      << dump_wally_psbt_outputs(psbt->outputs, psbt->num_outputs);
	ostrm << ", \"unknowns\":" << dump_wally_unknowns_map(psbt->unknowns);
	ostrm << ", \"version\":" << psbt->version;
	ostrm << " }";
	return ostrm.str();
}

string dump_tx(const struct bitcoin_tx *tx)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "\"wtx\":" << dump_wally_tx(tx->wtx);
	ostrm << ", \"psbt\":" << dump_wally_psbt(tx->psbt);
	ostrm << " }";
	return ostrm.str();
}
