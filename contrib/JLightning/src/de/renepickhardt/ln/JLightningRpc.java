package de.renepickhardt.ln;
/**
 * JLightningRpc extends the UnixDomainSocketRpc and exposes the specific 
 * API that is provided by c-lightning. It  is a java client library for the 
 * c-lightning node. It connects to c-lightning via a Unix Domain Socket over
 * JsonRPC v2.0 
 * 
 * This file is basically a port of the pylightning python client library
 * that comes with c-lightning.
 * 
 * The Author of this Java Client library is Rene Pickhardt. 
 * He also holds the copyright of this file. The library is licensed with
 * a BSD-style license. Have a look at the LICENSE file. 
 * 
 * If you like this library consider a donation via bitcoin or the lightning
 * network at http://ln.rene-pickhardt.de
 * 
 * @author Rene Pickhardt
 */

import java.util.HashMap;



public class JLightningRpc extends UnixDomainSocketRpc {

	public JLightningRpc(String socket_path) {
		super(socket_path);
		
	}
	
	/**
	 * Delete unpaid invoice {label} with {status}
	 * @param label of the invoice
	 * @param status status of the invoice
	 * @return
	 */
	public String delInvoice(String label, Status status) {
		HashMap<String, String> payload = new HashMap<String,String> ();
		payload.put("label", label);
		payload.put("status", status.toString());
		return this.call("delinvoice", payload);
	}
	
	public String getInfo() {
		return this.call("getinfo", null);
	}

	/**
	 * Show route to {id} for {msatoshi}, using {riskfactor} and optional
     * {cltv} (default 9). If specified search from {fromid} otherwise use
     * this node as source. Randomize the route with up to {fuzzpercent}
     * (0.0 -> 100.0, default 5.0) using {seed} as an arbitrary-size string
     * seed.
	 * 
	 * @param peer_id 
	 * @param msatoshi
	 * @param riskfactor
	 * @param cltv
	 * @param from_id
	 * @param fuzzpercent
	 * @param seed
	 * @return
	 */
	public String getRoute(String peer_id, int msatoshi, float riskfactor, int cltv, String from_id, float fuzzpercent, String seed) {
		HashMap<String, String> payload = new HashMap<String,String> ();
		payload.put("id", peer_id);
		payload.put("msatoshi", Integer.toString(msatoshi));
		payload.put("riskfactor", Float.toString(riskfactor));
		payload.put("cltv", Integer.toString(cltv));
		payload.put("fromid", from_id);
		payload.put("fuzzpercent", Float.toString(fuzzpercent));
		payload.put("seed", seed);
		return this.call("getroute", payload);
	}
	
	/**
	 * Create an invoice for {msatoshi} with {label} and {description} with
	 * optional {expiry} seconds (default 1 hour)
	 * 
	 * @param msatoshi
	 * @param label
	 * @param description
	 * @param expiry
	 * @param fallbacks
	 * @param preimage
	 * @return
	 */
	public String invoice (int msatoshi,String label, String description, int expiry,String fallbacks, String preimage) {		
		HashMap<String, String> payload = new HashMap<String,String> ();
		payload.put("msatoshi", Integer.toString(msatoshi));
		payload.put("label", label);
		payload.put("description", description);
		payload.put("expiry", Integer.toString(expiry));
		payload.put("fallbacks", fallbacks);
		payload.put("preimage", preimage);
		return this.call("invoice", payload);
	}
	
	/**
	 * Show funds available for opening channels and open channels
	 * @return
	 */
	public String listFunds() {
		return this.call("listfunds", null);
	}
	
	/**
	 * Show all known channels, accept optional {short_channel_id}
	 */
	public String listChannels(String short_channel_id) {		
		HashMap<String, String> payload = new HashMap<String,String> ();
		payload.put("short_channel_id", short_channel_id);
		return this.call("listchannels", payload);
	}	
	
	/**
	 * Show invoice {label} (or all, if no {label))
	 * @param label for a specific invoice to look up
	 * @return
	 */
	public String listInvoices(String label) {
		HashMap<String, String> payload = new HashMap<String,String> ();
		payload.put("label", label);
		return this.call("listinvoices", payload);
	}	
	
	public String listNodes(String node_id) {
		HashMap<String, String> payload = new HashMap<String,String> ();
		payload.put("id", node_id);
		return this.call("listnodes", payload);
	}
	
	/**
	 * Wait for the next invoice to be paid, after {lastpay_index}
     * (if supplied)
	 * @param last_payindex
	 * @return
	 */
	public String waitAnyInvoice(int last_payindex) {
		HashMap<String, String> payload = new HashMap<String,String> ();
		payload.put("last_pay_index", Integer.toString(last_payindex));
		return this.call("waitanyinvoice", payload);
	}
	
	
}
