package de.renepickhardt.ln;

/**
 * JLightning a small test / example class to demonstrate how to use JLightningRpc
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

public class JLightning {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		JLightningRpc rpc_interface = new JLightningRpc("/tmp/spark-env/ln1/lightning-rpc");
		String res = rpc_interface.listInvoices(null);
		System.out.println(res);
		res = rpc_interface.listFunds();
		System.out.println(res);
		res = rpc_interface.listInvoices(null);
		System.out.println(res);

	}


}
