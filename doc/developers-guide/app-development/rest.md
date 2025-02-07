---
title: "REST APIs"
slug: "rest"
hidden: false
createdAt: "2023-09-05T09:54:01.784Z"
updatedAt: "2023-10-13T09:54:01.784Z"
---

# CLNRest

CLNRest is a lightweight Rust-based built-in Core Lightning plugin (from v23.08) that transforms RPC calls into a REST service. 
It also broadcasts Core Lightning notifications to listeners connected to its websocket server. By generating REST API endpoints, 
it enables the execution of Core Lightning's RPC methods behind the scenes and provides responses in JSON format.

An online demo for the REST interface is available at [REST API REFERENCE](ref:get_list_methods_resource).

> 📘 Pro-tip
> 
> [REST API REFERENCE](ref:get_list_methods_resource) can also be tested with your own server.
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
> - Default `clnrest-host` is `127.0.0.1` but this testing will require it to be `0.0.0.0`.
>
> Note: This setup is for **testing only**. It is **highly recommended** to test with _non-mainnet_ (regtest/testnet) setup only.


## Installation

Note: if you have the older c-lightning-REST plugin, you can configure Core Lightning with `disable-plugin=clnrest`
option to avoid confusion with this one. You can also run both plugins simultaneously till all your applications
are not migrated to `clnrest`.


## Configuration

If `clnrest-port` is not specified, the plugin will disable itself.

- --clnrest-port: Sets the REST server port to listen to (3010 is common)

- --clnrest-protocol: Specifies the REST server protocol. Default is HTTPS.

- --clnrest-host: Defines the REST server host. Default is 127.0.0.1.

- --clnrest-certs: Defines the path for HTTPS cert & key. Default path is same as RPC file path to utilize gRPC's client certificate.
If it is missing at the configured location, new identity will be generated.

- --clnrest-csp: Creates a whitelist of trusted content sources that can run on a webpage and helps mitigate the risk of attacks. 
Default CSP:
`default-src 'self'; font-src 'self'; img-src 'self' data:; frame-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';`
Example CSP:
`clnrest-csp=default-src 'self'; font-src 'self'; img-src 'self'; frame-src 'self'; style-src 'self'; script-src 'self';`.

- --clnrest-cors-origins: Define multiple origins which are allowed to share resources on web pages to a domain different from the 
one that served the web page. Default is `*` which allows all origins. Example to define multiple origins:

```
clnrest-cors-origins=https://localhost:5500
clnrest-cors-origins=http://192.168.1.50:3030
clnrest-cors-origins=https?://127.0.0.1:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])

```

- --clnrest-swagger-root: Root url for Swagger UI. Default is `/`. Example: `clnrest-swagger-root=/doc`

## Server

With the default configurations, the Swagger user interface will be available at https://127.0.0.1:3010/. 
The POST method requires `rune` header for authorization.

- A new `rune` can be created via [createrune](https://docs.corelightning.org/reference/lightning-createrune) or the list of 
existing runes can be retrieved with [showrunes](https://docs.corelightning.org/reference/lightning-showrunes) command.

Note: in version v23.08, a parameter `Nodeid` was required to be the id of the node we're talking to (see `id (pubkey)` received 
from [getinfo](https://docs.corelightning.org/reference/lightning-getinfo)). You can still send this for backwards compatibility, 
but it is completely ignored.

### cURL
Example curl command for POST will also require a `rune` header like below:
    `curl -k -X POST 'https://localhost:3010/v1/getinfo' -H 'Rune: <node-rune>'`

With `-k` or `--insecure` option curl proceeds with the connection even if the SSL certificate cannot be verified.
This option should be used only when testing with self signed certificate.

## Websocket Server
Websocket server is available at `https://127.0.0.1:3010`. clnrest broadcasts notifications to all listeners. 

This websocket server requires a `rune` with at least `readonly` access for authorization. The default method used
for current validation is `listclnrest-notifications`. User can either provided a rune with minimum `readonly`
access or can create a new special purpose rune, only for websocket validation, with restrictions='[["method=listclnrest-notifications"]]'.
The client will only receive notifications if `rune`, provided in headers, allows it.

### Websocket client examples

#### Python

```python
import socketio
import requests

http_session = requests.Session()
http_session.verify = True
http_session.headers.update({
    "rune": "your-generated-rune"
})
sio = socketio.Client(http_session=http_session)

@sio.event
def connect():
    print("Client Connected")

@sio.event
def disconnect():
    print(f"Server connection closed.\nCheck CLN logs for errors if unexpected")

@sio.event
def message(data):
    print(f"Message from server: {data}")

@sio.event
def error(err):
    print(f"Error from server: {err}")

sio.connect('http://127.0.0.1:3010')

sio.wait()

```

#### NodeJS

```javascript
const io = require('socket.io-client');

const socket = io.connect('http://127.0.0.1:3010', {extraHeaders: {rune: "your-generated-rune"}});

socket.on('connect', function() {
  console.log('Client Connected');
});

socket.on('disconnect', function(reason) {
  console.log('Server connection closed: ', reason, '\nCheck CLN logs for errors if unexpected');
});

socket.on('message', function(data) {
  console.log('Message from server: ', data);
});

socket.on('error', function(err) {
  console.error('Error from server: ', err);
});

```

#### HTML

```html
<!DOCTYPE html>
<html>
<head>
    <title>Socket.IO Client Example</title>
    <script src="https://cdn.socket.io/4.0.1/socket.io.min.js"></script>
</head>
<body>
    <h1>Socket.IO Client Example</h1>
    <hr>
    <h3>Status:</h3>
    <div id="status">Not connected</div>
    <hr>
    <h3>Send Message:</h3>
    <input type="text" id="messageInput" placeholder="Type your message here">
    <button onclick="sendMessage()">Send</button>
    <hr>
    <h3>Received Messages:</h3>
    <div id="messages"></div>
    <script>
        const statusElement = document.getElementById('status');
        const messagesElement = document.getElementById('messages');

        const socket = io('http://127.0.0.1:3010', {extraHeaders: {rune: "your-generated-rune"}});

        socket.on('connect', () => {
            statusElement.textContent = 'Client Connected';
        });

        socket.on('disconnect', (reason) => {
            statusElement.textContent = 'Server connection closed: ' + reason + '\n Check CLN logs for errors if unexpected';
        });

        socket.on('message', (data) => {
            const item = document.createElement('li');
            item.textContent = JSON.stringify(data);
            messagesElement.appendChild(item);
            console.log('Message from server: ', data);
        });

        socket.on('error', (err) => {
            const item = document.createElement('li');
            item.textContent = JSON.stringify(err);
            messagesElement.appendChild(item);
            console.error('Error from server: ', err);
        });

        function sendMessage() {
            const message = messageInput.value;
            if (message) {
                socket.emit('message', message);
                messageInput.value = '';
            }
        }
    </script>
</body>
</html>

```
