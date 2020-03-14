#include <iostream>
#include <sstream>

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
#include <secp256k1_recovery.h>
}

#include "contrib/remote_hsmd/dump.h"

using std::ostringstream;
using std::string;

/* type_to_string has issues in the C++ environment, use this to
   dump binary data as hex instead. */
string dump_hex(const void *vptr, size_t sz)
{
	static const char hex[] = "0123456789abcdef";
	string retval(sz*2, '\0');
	uint8_t const * ptr = (uint8_t const *) vptr;
	for (size_t ii = 0; ii < sz; ++ii) {
		retval[ii*2+0] = hex[(*ptr) >> 4];
		retval[ii*2+1] = hex[(*ptr) & 0xf];
		ptr++;
	}
	return retval;
}

string dump_bitcoin_txid(const struct bitcoin_txid *txid)
{
	return dump_hex(txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
}

string dump_bitcoin_signature(const struct bitcoin_signature *sp)
{
	ostringstream ostrm;
	ostrm << "{ "
	      << "sighash_type=" << int(sp->sighash_type)
	      << "s=" << dump_secp256k1_ecdsa_signature(&sp->s)
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

string dump_signatures(const u8 **sp)
{
	ostringstream ostrm;
 	ostrm << "[";
	for (size_t input_ndx = 0; input_ndx < tal_count(sp); ++input_ndx) {
		if (input_ndx != 0)
			ostrm << " ";
		u8 const *sig = sp[input_ndx];
		ostrm << dump_hex(sig, tal_count(sig));
	}
 	ostrm << "]";
	return ostrm.str();
}

string dump_basepoints(const struct basepoints *bp)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "revocation=" << dump_pubkey(&bp->revocation);
	ostrm << ", payment=" << dump_pubkey(&bp->payment);
	ostrm << ", htlc=" << dump_pubkey(&bp->htlc);
	ostrm << ", delayed_payment=" << dump_pubkey(&bp->delayed_payment);
	ostrm << " }";
	return ostrm.str();
}

string dump_unilateral_close_info(const struct unilateral_close_info *ip)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "channel_id=" << ip->channel_id;
	ostrm << ", peer_id=" << dump_node_id(&ip->peer_id);
	ostrm << ", commitment_point=" <<
		(ip->commitment_point ? dump_pubkey(ip->commitment_point) :
		 "<none>");
	ostrm << " }";
	return ostrm.str();
}

string dump_utxo(const struct utxo *in)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "txid=" << dump_bitcoin_txid(&in->txid);
	ostrm << ", outnum=" << in->outnum;
	ostrm << ", amount=" << in->amount.satoshis;
	ostrm << ", keyindex=" << in->keyindex;
	ostrm << ", is_p2sh=" << in->is_p2sh;
	ostrm << ", close_info=" <<
		(in->close_info ?
		 dump_unilateral_close_info(in->close_info) :
		 "<none>");
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
	ostrm << "amount=" << op->amount.satoshis;
	ostrm << ", script=" <<
	   (op->script ? dump_hex(op->script, tal_count(op->script)) : "<none>");
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

string dump_input_amounts(const struct amount_sat **ias)
{
	ostringstream ostrm;
	ostrm << "[";
	if (*ias) {
		for (size_t ii = 0; ii < tal_count(ias); ii++) {
			if (ii != 0)
				ostrm << ",";
			ostrm << ias[ii]->satoshis;
		}
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_wally_tx_witness_stack(const struct wally_tx_witness_stack *sp)
{
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

string dump_wally_tx_input(const struct wally_tx_input *in)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "txhash=" << dump_hex(in->txhash, sizeof(in->txhash));
	ostrm << ", index=" << in->index;
	ostrm << ", sequence=" << in->sequence;
	ostrm << ", script=" <<
		(in->script_len ? dump_hex(in->script, in->script_len) :
		 "<none>");
	ostrm << ", witness=" <<
		(in->witness ? dump_wally_tx_witness_stack(in->witness) :
		 "<none>");
	ostrm << ", features=" << int(in->features);
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
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "satoshi=" << out->satoshi;
	ostrm << " script=" <<
		(out->script_len ? dump_hex(out->script, out->script_len) :
		 "<none>");
	ostrm << ", features=" << int(out->features);
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
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "version=" << wtx->version;
	ostrm << ", locktime=" << wtx->locktime;
	ostrm << ", inputs=" <<
		dump_wally_tx_inputs(wtx->inputs, wtx->num_inputs);
	ostrm << ", inputs_allocation_len=" << wtx->inputs_allocation_len;
	ostrm << ", outputs=" <<
		dump_wally_tx_outputs(wtx->outputs, wtx->num_outputs);
	ostrm << ", outputs_allocation_len=" << wtx->outputs_allocation_len;
	ostrm << " }";
	return ostrm.str();
}

string dump_output_witscripts(const struct witscript **wp)
{
	ostringstream ostrm;
	ostrm << "[";
	for (size_t ii = 0; ii < tal_count(wp); ii++) {
		if (ii != 0)
			ostrm << ",";
		ostrm << (wp[ii] ?
			  dump_hex(wp[ii]->ptr, tal_count(wp[ii]->ptr)) :
			  "<none>");
	}
	ostrm << "]";
	return ostrm.str();
}

string dump_tx(const struct bitcoin_tx *tx)
{
	ostringstream ostrm;
	ostrm << "{ ";
	ostrm << "input_amounts=" <<
		dump_input_amounts(
			(const struct amount_sat **)tx->input_amounts);
	ostrm << ", wally_tx=" << dump_wally_tx(tx->wtx);
	ostrm << ", output_witscripts=" <<
		dump_output_witscripts(
			(const struct witscript **)tx->output_witscripts);
	ostrm << " }";
	return ostrm.str();
}
