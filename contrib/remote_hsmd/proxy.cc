/* This needs to be first */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <sys/types.h>	/* These two only needed for sleep() and getpid() */
#include <unistd.h>

#include <iostream>
#include <sstream>

#include <grpc++/grpc++.h>

extern "C" {
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <common/derive_basepoints.h>
#include <common/hash_u5.h>
#include <common/node_id.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/utxo.h>
#include <secp256k1_recovery.h>
#include <wally_bip32.h>
}

#include "contrib/remote_hsmd/remotesigner.pb.h"
#include "contrib/remote_hsmd/remotesigner.grpc.pb.h"

#include "contrib/remote_hsmd/dump.h"
#include "contrib/remote_hsmd/proxy.h"

using std::cerr;
using std::endl;
using std::ostringstream;
using std::string;
using std::unique_ptr;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

using ::google::protobuf::RepeatedPtrField;

using namespace remotesigner;

namespace {
unique_ptr<Signer::Stub> stub;
string last_message;
struct node_id self_id;

proxy_stat map_status(Status const & status)
{
	StatusCode code = status.error_code();

	// FIXME - this is bogus, but the pytest framework loses our
	// status_unusual messages.
	if (code != StatusCode::OK) {
		cerr << "PROXY-HSMD grpc::StatusCode " << int(code)
		     << ": " << status.error_message()
		     << endl;
	}
	switch (code) {
	case StatusCode::OK:			return PROXY_OK;
	case StatusCode::CANCELLED:		return PROXY_CANCELLED;
	case StatusCode::DEADLINE_EXCEEDED:	return PROXY_TIMEOUT;
	case StatusCode::UNAVAILABLE:		return PROXY_UNAVAILABLE;
	case StatusCode::INVALID_ARGUMENT:	return PROXY_INVALID_ARGUMENT;
	case StatusCode::INTERNAL:		return PROXY_INTERNAL_ERROR;
	default:
		cerr << "UNHANDLED grpc::StatusCode " << int(code)
		     << ": " << status.error_message()
		     << endl;
		abort();
	}
}

/* BIP144:
 * If the witness is empty, the old serialization format should be used. */
bool uses_witness(const struct bitcoin_tx *tx)
{
	size_t i;
	for (i = 0; i < tx->wtx->num_inputs; i++) {
		if (tx->wtx->inputs[i].witness)
			return true;
	}
	return false;
}


string serialized_tx(struct bitcoin_tx const *tx, bool bip144)
{
	int res;
	size_t len, written;
	u8 *serialized;;
	u8 flag = 0;

	if (bip144 && uses_witness(tx))
		flag |= WALLY_TX_FLAG_USE_WITNESS;

	res = wally_tx_get_length(tx->wtx, flag, &len);
	assert(res == WALLY_OK);

	string retval(len, '\0');
	res = wally_tx_to_bytes(tx->wtx, flag, (unsigned char *)&retval[0],
				retval.size(), &written);
	assert(res == WALLY_OK);
	assert(len == written);
	return retval;
}

void marshal_channel_nonce(struct node_id const *peer_id, u64 dbid,
			   ChannelNonce *o_np)
{
	o_np->set_data(string((char const *)peer_id->k, sizeof(peer_id->k)) +
		       string((char const *)&dbid, sizeof(dbid)));
}

void marshal_secret(struct secret const *ss, Secret *o_sp)
{
	o_sp->set_data(ss->data, sizeof(ss->data));
}

void marshal_node_id(struct node_id const *np, NodeId *o_np)
{
	o_np->set_data(np->k, sizeof(np->k));
}

void marshal_pubkey(struct pubkey const *pp, PubKey *o_pp)
{
	o_pp->set_data(pp->pubkey.data, sizeof(pp->pubkey.data));
}

void marshal_utxo(struct utxo const *up, InputDescriptor *idesc)
{
	idesc->mutable_key_loc()->set_key_index(up->keyindex);
	idesc->mutable_prev_output()->set_value(up->amount.satoshis);
	/* FIXME - where does pk_script come from? */
	idesc->set_spend_type(up->is_p2sh
			      ? SpendType::P2SH_P2WPKH
			      : SpendType::P2WPKH);
	if (up->close_info) {
		UnilateralCloseInfo *cinfo = idesc->mutable_close_info();
		marshal_channel_nonce(&up->close_info->peer_id,
				      up->close_info->channel_id,
				      cinfo->mutable_channel_nonce());
		if (up->close_info->commitment_point)
			marshal_pubkey(up->close_info->commitment_point,
				       cinfo->mutable_commitment_point());
	}
}

void marshal_single_input_tx(struct bitcoin_tx const *tx,
			     u8 const *output_witscript,
			     struct witscript const **output_witscripts,
			     Transaction *o_tp)
{
	if (output_witscript) {
		/* Called with a single witscript. */
		assert(tx->wtx->num_outputs == 1);
	} else if (output_witscripts) {
		/* Called with an array of witscripts. */
		assert(tal_count(output_witscripts) == tx->wtx->num_outputs);
	}

	o_tp->set_raw_tx_bytes(serialized_tx(tx, true));

	assert(tx->wtx->num_inputs == 1);
	InputDescriptor *idesc = o_tp->add_input_descs();
	idesc->mutable_prev_output()->set_value(tx->input_amounts[0]->satoshis);
	/* FIXME - What else needs to be set? */

	for (size_t ii = 0; ii < tx->wtx->num_outputs; ii++) {
		OutputDescriptor *odesc = o_tp->add_output_descs();
		if (output_witscript) {
			/* We have a single witscript. */
			odesc->set_witscript((const char *) output_witscript,
					     tal_count(output_witscript));
		} else if (output_witscripts) {
			/* We have an array of witscripts. */
			if (output_witscripts[ii])
				odesc->set_witscript(
					(const char *)
					output_witscripts[ii]->ptr,
					tal_count(output_witscripts[ii]->ptr));
			else
				odesc->set_witscript("");
		} else {
			/* Called w/ no witscripts. */
			odesc->set_witscript("");
		}

	}
}

void unmarshal_secret(Secret const &ss, struct secret *o_sp)
{
	assert(ss.data().size() == sizeof(o_sp->data));
	memcpy(o_sp->data, ss.data().data(), sizeof(o_sp->data));

}
void unmarshal_node_id(NodeId const &nn, struct node_id *o_np)
{
	assert(nn.data().size() == sizeof(o_np->k));
	memcpy(o_np->k, nn.data().data(), sizeof(o_np->k));
}

void unmarshal_pubkey(PubKey const &pk, struct pubkey *o_pp)
{
	bool ok = pubkey_from_der((u8 const *)pk.data().data(),
				  pk.data().size(),
				  o_pp);
	assert(ok);
}

void unmarshal_ext_pubkey(ExtPubKey const &xpk, struct ext_key *o_xp)
{
	int rv = bip32_key_from_base58(xpk.encoded().data(), o_xp);
	assert(rv == WALLY_OK);
}

void unmarshal_bitcoin_signature(BitcoinSignature const &bs,
			      struct bitcoin_signature *o_sig)
{
	bool ok = signature_from_der(
		(const u8*)bs.data().data(),
		bs.data().size(),
		o_sig);
	assert(ok);
}

void unmarshal_ecdsa_signature(ECDSASignature const &es,
			    secp256k1_ecdsa_signature *o_sig)
{
	int ok = secp256k1_ecdsa_signature_parse_der(
		secp256k1_ctx,
		o_sig,
		(const u8*)es.data().data(),
		es.data().size());
	assert(ok);
}

void unmarshal_ecdsa_recoverable_signature(ECDSARecoverableSignature const &es,
			    secp256k1_ecdsa_recoverable_signature *o_sig)
{
	assert(es.data().size() == 65);
	int recid = es.data().data()[64];
	int ok = secp256k1_ecdsa_recoverable_signature_parse_compact(
		secp256k1_ctx,
		o_sig,
		(const u8*)es.data().data(),
		recid);
	assert(ok);
}

void unmarshal_witnesses(RepeatedPtrField<Witness> const &wits, u8 ****o_wits)
{
	u8 ***owits = NULL;
	int nwits = wits.size();
	if (nwits > 0) {
		owits = tal_arrz(tmpctx, u8**, nwits);
		for (size_t ii = 0; ii < nwits; ++ii) {
			owits[ii] = tal_arrz(owits, u8*, 2);
			Witness const &wit = wits[ii];
			const string &sig = wit.signature().data();
			const string &pubkey = wit.pubkey().data();
			owits[ii][0] = tal_arr(owits[ii], u8, sig.size());
			memcpy(owits[ii][0], sig.data(), sig.size());
			owits[ii][1] = tal_arr(owits[ii], u8, pubkey.size());
			memcpy(owits[ii][1], pubkey.data(), pubkey.size());
		}
	}
	*o_wits = owits;
}

/* Copied from ccan/mem/mem.h which the c++ compiler doesn't like */
static inline bool memeq(const void *a, size_t al, const void *b, size_t bl)
{
	return al == bl && !memcmp(a, b, bl);
}

} /* end namespace */

extern "C" {
const char *proxy_last_message(void)
{
	return last_message.c_str();
}

void proxy_setup()
{
	status_debug("%s:%d %s", __FILE__, __LINE__, __FUNCTION__);
	auto channel = grpc::CreateChannel("localhost:50051",
					   grpc::InsecureChannelCredentials());
	stub = Signer::NewStub(channel);
	last_message = "";
}

proxy_stat proxy_init_hsm(struct bip32_key_version *bip32_key_version,
			  struct chainparams const *chainparams,
			  struct secret *hsm_secret,
			  struct node_id *o_node_id,
			  struct ext_key *o_ext_pubkey)
{
	status_debug(
		"%s:%d %s hsm_secret=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_secret(hsm_secret).c_str()
		);

	/* First we make the Init call to create the Node. */
	{
		last_message = "";
		InitRequest req;

		auto cp = req.mutable_chainparams();
		cp->set_network_name(chainparams->network_name);

		/* FIXME - Sending the secret instead of generating on
		 * the remote. */
		marshal_secret(hsm_secret, req.mutable_hsm_secret());

		ClientContext context;
		InitReply rsp;
		Status status = stub->Init(&context, req, &rsp);
		if (status.ok()) {
			unmarshal_node_id(rsp.node_id(), o_node_id);
			unmarshal_node_id(rsp.node_id(), &self_id);
			status_debug("%s:%d %s node_id=%s",
				     __FILE__, __LINE__, __FUNCTION__,
				     dump_node_id(o_node_id).c_str());
			last_message = "success";
			// Fall-through to the next part. */
		} else {
			status_unusual("%s:%d %s: %s",
				       __FILE__, __LINE__, __FUNCTION__,
				       status.error_message().c_str());
			last_message = status.error_message();
			return map_status(status);
		}
	}

	/* Next we make the GetExtPubKey call to fetch the XPUB. */
	{
		last_message = "";
		GetExtPubKeyRequest req;

		marshal_node_id(&self_id, req.mutable_node_id());

		ClientContext context;
		GetExtPubKeyReply rsp;
		Status status = stub->GetExtPubKey(&context, req, &rsp);
		if (status.ok()) {
			unmarshal_ext_pubkey(rsp.xpub(), o_ext_pubkey);
			status_debug("%s:%d %s node_id=%s ext_pubkey=%s",
				     __FILE__, __LINE__, __FUNCTION__,
				     dump_node_id(&self_id).c_str(),
				     dump_ext_pubkey(o_ext_pubkey).c_str());
			last_message = "success";
			return PROXY_OK;
		} else {
			status_unusual("%s:%d %s: %s",
				       __FILE__, __LINE__, __FUNCTION__,
				       status.error_message().c_str());
			last_message = status.error_message();
			return map_status(status);
		}
	}
}

proxy_stat proxy_handle_ecdh(const struct pubkey *point,
			     struct secret *o_ss)
{
	status_debug(
		"%s:%d %s self_id=%s point=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_pubkey(point).c_str()
		);

	last_message = "";
	ECDHRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_pubkey(point, req.mutable_point());

	ClientContext context;
	ECDHReply rsp;
	Status status = stub->ECDH(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_secret(rsp.shared_secret(), o_ss);
		status_debug("%s:%d %s self_id=%s ss=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secret(o_ss).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_pass_client_hsmfd(
	struct node_id *peer_id,
	u64 dbid,
	u64 capabilities)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"capabilities=%" PRIu64 "",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		capabilities
		);

	last_message = "";
	NewChannelRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());

	ClientContext context;
	NewChannelReply rsp;
	Status status = stub->NewChannel(&context, req, &rsp);
	if (status.ok()) {
		status_debug("%s:%d %s self_id=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_withdrawal_tx(
	struct node_id *peer_id,
	u64 dbid,
	struct amount_sat *satoshi_out,
	struct amount_sat *change_out,
	u32 change_keyindex,
	struct bitcoin_tx_output **outputs,
	struct utxo **utxos,
	struct bitcoin_tx *tx,
	u8 ****o_wits)
{
	fprintf(stderr,
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"satoshi_out=%" PRIu64 " change_out=%" PRIu64 " "
		"change_keyindex=%u utxos=%s outputs=%s tx=%s\n",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		satoshi_out->satoshis,
		change_out->satoshis,
		change_keyindex,
		dump_utxos((const struct utxo **)utxos).c_str(),
		dump_bitcoin_tx_outputs(
			(const struct bitcoin_tx_output **)outputs).c_str(),
		dump_tx(tx).c_str()
		);

	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"satoshi_out=%" PRIu64 " change_out=%" PRIu64 " "
		"change_keyindex=%u utxos=%s outputs=%s tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		satoshi_out->satoshis,
		change_out->satoshis,
		change_keyindex,
		dump_utxos((const struct utxo **)utxos).c_str(),
		dump_bitcoin_tx_outputs(
			(const struct bitcoin_tx_output **)outputs).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignFundingTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());

	req.mutable_tx()->set_raw_tx_bytes(serialized_tx(tx, true));
	assert(tx->wtx->num_inputs == tal_count(utxos));
	for (size_t ii = 0; ii < tx->wtx->num_inputs; ii++)
		marshal_utxo(utxos[ii], req.mutable_tx()->add_input_descs());

	/* We expect exactly two total ouputs, with one non-change. */
	/* FIXME - next assert fails in
	   tests/test_closing.py::test_onchain_unwatch with num_outputs == 1
        assert(tx->wtx->num_outputs == 2);
	*/
	assert(tal_count(outputs) == 1);
	for (size_t ii = 0; ii < tx->wtx->num_outputs; ii++) {
	 	const struct wally_tx_output *out = &tx->wtx->outputs[ii];
		OutputDescriptor *odesc = req.mutable_tx()->add_output_descs();
		/* Does this output match the funding output? */
		if (memeq(out->script, out->script_len,
			  outputs[0]->script, tal_count(outputs[0]->script))) {
			/* Yes, this is the funding output. */
			/* FIXME - we don't set anything? */
		} else {
			/* Nope, this must be the change output. */
			assert(out->satoshi == change_out->satoshis);
			odesc->mutable_key_loc()->
				set_key_index(change_keyindex);
		}
	}

	ClientContext context;
	SignFundingTxReply rsp;
	Status status = stub->SignFundingTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_witnesses(rsp.witnesses(), o_wits);
		fprintf(stderr, "%s:%d %s self_id=%s witnesses=%s\n",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_witnesses((u8 const ***) *o_wits).c_str());
		status_debug("%s:%d %s self_id=%s witnesses=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_witnesses((u8 const ***) *o_wits).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		fprintf(stderr, "%s:%d %s: self_id=%s %s\n",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_remote_commitment_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *remote_funding_pubkey,
	struct amount_sat *funding,
	struct node_id *peer_id,
	u64 dbid,
	struct witscript const **output_witscripts,
	const struct pubkey *remote_per_commit,
	bool option_static_remotekey,
	struct bitcoin_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"funding=%" PRIu64 " remote_funding_pubkey=%s "
		"output_witscripts=%s remote_per_commit=%s "
		"option_static_remotekey=%s  tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		funding->satoshis,
		dump_pubkey(remote_funding_pubkey).c_str(),
		dump_output_witscripts(output_witscripts).c_str(),
		dump_pubkey(remote_per_commit).c_str(),
		(option_static_remotekey ? "true" : "false"),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignRemoteCommitmentTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_pubkey(remote_funding_pubkey,
		       req.mutable_remote_funding_pubkey());
	marshal_pubkey(remote_per_commit,
		       req.mutable_remote_per_commit_point());
	req.set_option_static_remotekey(option_static_remotekey);
	marshal_single_input_tx(tx, NULL, output_witscripts, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignRemoteCommitmentTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_get_per_commitment_point(
	struct node_id *peer_id,
	u64 dbid,
	u64 n,
	struct pubkey *o_per_commitment_point,
	struct secret **o_old_secret)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"n=%" PRIu64 "",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		n
		);

	last_message = "";
	GetPerCommitmentPointRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_n(n);

	ClientContext context;
	GetPerCommitmentPointReply rsp;
	Status status = stub->GetPerCommitmentPoint(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_pubkey(rsp.per_commitment_point(),
			      o_per_commitment_point);
		if (rsp.old_secret().data().empty()) {
			*o_old_secret = NULL;
		} else {
			*o_old_secret = tal_arr(tmpctx, struct secret, 1);
			unmarshal_secret(rsp.old_secret(), *o_old_secret);
		}
		status_debug("%s:%d %s self_id=%s "
			     "per_commitment_point=%s old_secret=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_pubkey(o_per_commitment_point).c_str(),
			     (*o_old_secret ?
			      dump_secret(*o_old_secret).c_str() : "<none>"));
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_invoice(
	u5 *u5bytes,
	u8 *hrpu8,
	secp256k1_ecdsa_recoverable_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s u5bytes=%s hrpu8=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(u5bytes, tal_count(u5bytes)).c_str(),
		string((const char *)hrpu8, tal_count(hrpu8)).c_str()
		);

	last_message = "";
	SignInvoiceRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	req.set_data_part(u5bytes, tal_count(u5bytes));
	req.set_human_readable_part((const char *)hrpu8, tal_count(hrpu8));

	ClientContext context;
	RecoverableNodeSignatureReply rsp;
	Status status = stub->SignInvoice(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_recoverable_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_recoverable_signature(
				     o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_message(
	u8 *msg,
	secp256k1_ecdsa_recoverable_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s msg=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(msg, tal_count(msg)).c_str()
		);

	last_message = "";
	SignMessageRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	req.set_message(msg, tal_count(msg));

	ClientContext context;
	RecoverableNodeSignatureReply rsp;
	Status status = stub->SignMessage(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_recoverable_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_recoverable_signature(
				     o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_channel_update_sig(
	u8 *channel_update,
	secp256k1_ecdsa_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s "
		"channel_update=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(channel_update, tal_count(channel_update)).c_str());

	/* Skip the portion of the channel_update that we don't sign */
	size_t offset = 2 + 64;	/* sizeof(type) + sizeof(signature) */
	size_t annsz = tal_count(channel_update);

	last_message = "";
	SignChannelUpdateRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	req.set_channel_update(channel_update + offset, annsz - offset);

	ClientContext context;
	NodeSignatureReply rsp;
	Status status = stub->SignChannelUpdate(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_get_channel_basepoints(
	struct node_id *peer_id,
	u64 dbid,
	struct basepoints *o_basepoints,
	struct pubkey *o_funding_pubkey)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 "",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid
		);

	last_message = "";
	GetChannelBasepointsRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());

	ClientContext context;
	GetChannelBasepointsReply rsp;
	Status status = stub->GetChannelBasepoints(&context, req, &rsp);
	if (status.ok()) {
		Basepoints const & bps = rsp.basepoints();
		unmarshal_pubkey(bps.revocation(), &o_basepoints->revocation);
		unmarshal_pubkey(bps.payment(), &o_basepoints->payment);
		unmarshal_pubkey(bps.htlc(), &o_basepoints->htlc);
		unmarshal_pubkey(bps.delayed_payment(),
				 &o_basepoints->delayed_payment);
		unmarshal_pubkey(bps.funding_pubkey(), o_funding_pubkey);
		status_debug("%s:%d %s self_id=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_basepoints(o_basepoints).c_str(),
			     dump_pubkey(o_funding_pubkey).c_str());

		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_mutual_close_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *remote_funding_pubkey,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"remote_funding_pubkey=%s tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_pubkey(remote_funding_pubkey).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignMutualCloseTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_pubkey(remote_funding_pubkey,
		       req.mutable_remote_funding_pubkey());
	marshal_single_input_tx(tx, NULL, NULL, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignMutualCloseTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_commitment_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *remote_funding_pubkey,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"remote_funding_pubkey=%s tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_pubkey(remote_funding_pubkey).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignCommitmentTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_pubkey(remote_funding_pubkey,
		       req.mutable_remote_funding_pubkey());
	marshal_single_input_tx(tx, NULL, NULL, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignCommitmentTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_cannouncement_sig(
	struct node_id *peer_id,
	u64 dbid,
	u8 *channel_announcement,
	secp256k1_ecdsa_signature *o_node_sig,
	secp256k1_ecdsa_signature *o_bitcoin_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " ca=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_hex(channel_announcement,
			 tal_count(channel_announcement)).c_str()
		);

	/* Skip the portion of the channel_update that we don't sign */
	size_t offset = 2 + 256; /* sizeof(type) + 4*sizeof(signature) */
	size_t annsz = tal_count(channel_announcement);

	last_message = "";
	SignChannelAnnouncementRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_channel_announcement(channel_announcement + offset,
				     annsz - offset);

	ClientContext context;
	SignChannelAnnouncementReply rsp;
	Status status = stub->SignChannelAnnouncement(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_signature(rsp.node_signature(), o_node_sig);
		unmarshal_ecdsa_signature(rsp.bitcoin_signature(), o_bitcoin_sig);
		status_debug("%s:%d %s self_id=%s node_sig=%s bitcoin_sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_signature(o_node_sig).c_str(),
			     dump_secp256k1_ecdsa_signature(o_bitcoin_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_local_htlc_tx(
	struct bitcoin_tx *tx,
	u64 commit_num,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"commit_num==%" PRIu64 " "
		"wscript=%s "
		"tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		commit_num,
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignLocalHTLCTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_n(commit_num);
	marshal_single_input_tx(tx, wscript, NULL, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignLocalHTLCTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str()
			);
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_remote_htlc_tx(
	struct bitcoin_tx *tx,
	u8 *wscript,
	const struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"wscript=%s tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignRemoteHTLCTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_pubkey(remote_per_commit_point,
		       req.mutable_remote_per_commit_point());
	marshal_single_input_tx(tx, wscript, NULL, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignRemoteHTLCTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_delayed_payment_to_us(
	struct bitcoin_tx *tx,
	u64 commit_num,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"commit_num==%" PRIu64 " "
		"wscript=%s "
		"tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		commit_num,
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignDelayedPaymentToUsRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_n(commit_num);
	marshal_single_input_tx(tx, wscript, NULL, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignDelayedPaymentToUs(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_remote_htlc_to_us(
	struct bitcoin_tx *tx,
	u8 *wscript,
	const struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"wscript=%s tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignRemoteHTLCToUsRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_pubkey(remote_per_commit_point,
		       req.mutable_remote_per_commit_point());
	marshal_single_input_tx(tx, wscript, NULL, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignRemoteHTLCToUs(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_penalty_to_us(
	struct bitcoin_tx *tx,
	struct secret *revocation_secret,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"revocation_secret=%s "
		"wscript=%s "
		"tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_hex(revocation_secret->data,
			 sizeof(revocation_secret->data)).c_str(),
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignPenaltyToUsRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_secret(revocation_secret, req.mutable_revocation_secret());
	marshal_single_input_tx(tx, wscript, NULL, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignPenaltyToUs(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_check_future_secret(
	struct node_id *peer_id,
	u64 dbid,
	u64 n,
	struct secret *suggested,
	bool *o_correct)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"n=%" PRIu64 " suggested=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		n,
		dump_hex(suggested->data, sizeof(suggested->data)).c_str()
		);

	last_message = "";
	CheckFutureSecretRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_n(n);
	marshal_secret(suggested, req.mutable_suggested());

	ClientContext context;
	CheckFutureSecretReply rsp;
	Status status = stub->CheckFutureSecret(&context, req, &rsp);
	if (status.ok()) {
		*o_correct = rsp.correct();
		status_debug("%s:%d %s self_id=%s correct=%d",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(), int(*o_correct));
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_node_announcement(
	u8 *node_announcement,
	secp256k1_ecdsa_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s ann=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(node_announcement,
			 tal_count(node_announcement)).c_str()
		);

	/* Skip the portion of the channel_update that we don't sign */
	size_t offset = 2 + 64;	/* sizeof(type) + sizeof(signature) */
	size_t annsz = tal_count(node_announcement);

	last_message = "";
	SignNodeAnnouncementRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	req.set_node_announcement(node_announcement + offset, annsz - offset);

	ClientContext context;
	NodeSignatureReply rsp;
	Status status = stub->SignNodeAnnouncement(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_signature(rsp.signature(), o_sig);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

// FIXME - This routine allows us to pretty print the tx to stderr
// from C code.  Probably should remove it in production ...
void print_tx(char const *tag, struct bitcoin_tx const *tx)
{
	fprintf(stderr, "%s: tx=%s\n", tag, dump_tx(tx).c_str());
}

} /* extern "C" */
