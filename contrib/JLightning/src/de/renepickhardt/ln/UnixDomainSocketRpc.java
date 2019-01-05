package de.renepickhardt.ln;
/**
 * UnixDomainSocketRpc the base class to handle communication between
 * JLightning and the c-lightning node over the UnixDomainSocket 
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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;


import org.json.JSONException;
import org.json.JSONObject;
import org.newsclub.net.unix.AFUNIXSocket;
import org.newsclub.net.unix.AFUNIXSocketAddress;

public class UnixDomainSocketRpc {
	protected AFUNIXSocket sock;
	protected InputStream is;
	protected OutputStream os;
	protected static int id = 1;
	
	public UnixDomainSocketRpc(String socket_path) {
		File socketFile = new File(socket_path);
		try {
			this.sock = AFUNIXSocket.newInstance();
			this.sock.connect(new AFUNIXSocketAddress(socketFile));
			this.is = sock.getInputStream();
			this.os = sock.getOutputStream();			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public String call(String method, HashMap<String, String> payload) {
		// if no payload is given make empty one
		if(payload == null) {
			payload = new HashMap<String, String>();
		}
		
		//remove null items from payload
		Set<String> keySet = new HashSet<String>();
		for (String key: payload.keySet()) {
			keySet.add(key);
		}
		for(String k:keySet) {
			if(payload.get(k)==null){
				payload.remove(k);
			}
		}
		
		JSONObject json = new JSONObject();
		
		try {
			json.put("method", method);
			json.put("params", new JSONObject(payload));
			// FIXME: Use id field to dispatch requests
			json.put("id", Integer.toString(this.id++));
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		try {
			this.os.write(json.toString().getBytes("UTF-8"));
			this.os.flush();
			
			// FIXME: Using a StringBuilder would be preferable but not so easy
			String response = "";
			int buffSize = 1024;
			byte[] buf = new byte[buffSize];

			while(true) { 
				int read = this.is.read(buf);
				response = response + new String(buf, 0, read, "UTF-8");
				if(read <=0 || response.contains("\n\n" )) {
					break;
				}
			}
			json = new JSONObject(response);
			if (json.has("result")) {
				json = json.getJSONObject("result");
				return json.toString(2);
			}
			else if (json.has("error")) {
				json = json.getJSONObject("error");
				return json.toString(2);
			}
			else
				return "Could not Parse Response from Lightning Node: " + response;
			
		} catch (IOException e) {
			e.printStackTrace();
			// FIXME: make json rpc? 
			return "no Response from lightning node";
		} catch (JSONException e) {
			e.printStackTrace();
			return "Could not parse response from Lightning Node";
		}
		
	}
}
