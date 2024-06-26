---
title: "WSS Proxy"
slug: "wss-proxy"
hidden: false
createdAt: "2024-04-15T09:54:01.784Z"
updatedAt: "2024-04-15T09:54:01.784Z"
---

# WSS-Proxy

The WSS Proxy plugin is a Python-based proxy server. It facilitates encrypted communication between clients and WebSocket server. It acts as an intermediary, forwarding RPC JSON commands from the client to the WebSocket server. Once the WebSocket server processes these commands and generates a response, the proxy server relays that response back to the client. This creates a seamless interaction bridge between the client and server.


## Installation

The plugin is built-in with Core Lightning but its python dependencies are not, and must be installed separately.
Install required packages with `pip install -r plugins/wss-proxy/requirements.txt`.


## Configuration

> 🚧 
> 
> Note: The wss-proxy plugin expects CLN to be listening on a websocket.
>
> In other words, CLN config option `bind-addr` starting with `ws` (`bind-addr=ws:...`)
>
> is required for wss-proxy to connect.

If `wss-bind-addr` is not specified, the plugin will disable itself.

- --wss-bind-addr: WSS proxy address to connect with WS. Format <wss-host>:<wss-port>.

- --wss-certs: Defines the path for cert & key. Default path is same as RPC file path to utilize gRPC/clnrest's client certificate.
If it is missing at the configured location, new identity will be generated.

```
wss-bind-addr=127.0.0.1:5002
wss-certs=/home/user/.lightning/regtest
```

### lnmessage Client Example

```javascript
import Lnmessage from 'lnmessage';
import crypto from 'crypto';
import WebSocket from 'ws';
import fs from 'fs';

const NODE_PUBKEY = '025...26';
const WSS_PORT = 5002;
const NODE_IP = '127.0.0.1';
const RUNE = 'ZrAK...MA==';
const CERT_PATH = '/home/user/.lightning/regtest';

class SecureWebSocket extends WebSocket {
  constructor(url) {
    const options = {};
    options.rejectUnauthorized = false;
    options.cert = fs.readFileSync(`${CERT_PATH}/client.pem`);
    options.key = fs.readFileSync(`${CERT_PATH}/client-key.pem`);
    super(url, options);
  }
}

globalThis.WebSocket = SecureWebSocket;

async function connect() {
  const ln = new Lnmessage({
    ip: NODE_IP,
    remoteNodePublicKey: NODE_PUBKEY,
    privateKey: crypto.randomBytes(32).toString('hex'),
    logger: { info: console.log, warn: console.warn, error: console.error },
    wsProxy: `wss://${NODE_IP}:${WSS_PORT}`,
    port: WSS_PORT
  })
  await ln.connect();
  ln.commando({reqId: crypto.randomBytes(8).toString('hex'), method: 'getinfo', params: [], rune: RUNE}).then(res => {
    console.warn('[WARN - ' + new Date().toISOString() + '] - ' + 'GETINFO' + ':\n' + JSON.stringify(res));
  }).catch(err => {
    console.error('[ERROR - ' + new Date().toISOString() + '] - ' + 'GETINFO' + ':\n' + JSON.stringify(err));  
  });
}

connect();

```
