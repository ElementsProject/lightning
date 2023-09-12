---
title: "REST APIs"
slug: "rest"
hidden: false
createdAt: "2023-09-05T09:54:01.784Z"
updatedAt: "2023-09-05T09:54:01.784Z"
---

# CLNRest

CLNRest is a lightweight Python-based core lightning plugin that transforms RPC calls into a REST service. By generating REST API endpoints, it enables the execution of Core Lightning's RPC methods behind the scenes and provides responses in JSON format.

A complete documentation for the REST interface is available at [REST API REFERENCE](ref:get-a-list-of-all-valid-rpc-methods). 


> 📘 Pro-tip
> 
> [REST API REFERENCE](ref:post_rpc_method_resource) can also be tested with your own server.
>
> By default, the base URL is set to connect with the Blockstream-hosted regtest node. 
>
> However, it can be configured to connect to your own cln node as described below:
>
> - Select `{protocol}://{ip}:{port}/` from Base URL dropdown on the right section of the page.
>
> - Click on the right side of the dropdown and configure `protocol`, `ip` and `port` values according to your setup.
>
> - The `ip` should be configured with your system's public IP address.
>
> - Default `rest-host` is `127.0.0.1` but this testing will require it to be `0.0.0.0`.
>
> Note: This setup is for **testing only**. It is **highly recommended** to test with _non-mainnet_ (regtest/testnet) setup only.


## Installation

Install required packages with `pip install json5 flask flask_restx gunicorn pyln-client flask-socketio gevent gevent-websocket` or `pip install -r requirements.txt`.

Note: if you have the older c-lightning-rest plugin, you can use `disable-plugin clnrest.py` to avoid any conflict with this one.  Of course, you could use this one instead!

## Configuration

If `rest-port` is not specified, the plugin will disable itself.

- --rest-port: Sets the REST server port to listen to (3010 is common)
- --rest-protocol: Specifies the REST server protocol. Default is HTTPS.
- --rest-host: Defines the REST server host. Default is 127.0.0.1.
- --rest-certs: Defines the path for HTTPS cert & key. Default path is same as RPC file path to utilize gRPC's client certificate. If it is missing at the configured location, new identity (`client.pem` and `client-key.pem`) will be generated.

## Server

With the default configurations, the Swagger user interface will be available at https://127.0.0.1:3010/. The POST method requires `rune` header for authorization.

- A new `rune` can be created via [createrune](https://docs.corelightning.org/reference/lightning-createrune) or the list of existing runes can be retrieved with [listrunes](https://docs.corelightning.org/reference/lightning-listrunes) command.

Note: in version v23.08, a parameter `Nodeid` was required to be the id of the node we're talking to (see `id (pubkey)` received from [getinfo](https://docs.corelightning.org/reference/lightning-getinfo) ).  You can still send this for backwards compatiblity, but it is completely ignored.

### cURL
Example curl command for POST will also require a `rune` header like below:
    `curl -k -X POST 'https://127.0.0.1:3010/v1/getinfo' -H 'Rune: <node-rune>'`

With `-k` or `--insecure` option curl proceeds with the connection even if the SSL certificate cannot be verified.
This option should be used only when testing with self signed certificate.

## Websocket Server
Websocket server is available at `/ws` endpoint. clnrest queues up notifications received for a second then broadcasts them to listeners.

### Websocket client examples

#### Python

```python
import socketio
import requests

http_session = requests.Session()
http_session.verify = False
sio = socketio.Client(http_session=http_session)

@sio.event
def message(data):
    print(f'I received a message: {data}')

@sio.event
def connect():
    print("I'm connected!")

@sio.event
def disconnect():
    print("I'm disconnected!")

sio.connect('https://127.0.0.1:3010/ws')
sio.wait()

```

#### NodeJS

```javascript
const io = require('socket.io-client');

const socket = io.connect('https://127.0.0.1:3010', {rejectUnauthorized: false});

socket.on('connect', function() {
  console.log("I'm connected!");
});

socket.on('message', function(data) {
  console.log('I received a message: ', data);
});

socket.on('disconnect', function() {
  console.log("I'm disconnected!");
});

```
