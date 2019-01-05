package de.renepickhardt.ln;
/**
 * Named enum to encode the Status of invoices and payments
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
 * @author rpickhardt
 */
public enum Status {
	PAID("paid"), UNPAID("unpaid"), EXPIRED("expired");
	
	private final String statusDescription;

    private Status(String value) {
        statusDescription = value;
    }

    public String getStatusDescription() {
        return statusDescription;
    }
}
