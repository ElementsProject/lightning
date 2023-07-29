# CLNRest

CLNRest is a lightweight Python-based core lightning plugin that transforms RPC calls into a REST service. By generating REST API endpoints, it enables the execution of Core Lightning's RPC methods behind the scenes and provides responses in JSON format.

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

With the default configurations, the Swagger user interface will be available at https://127.0.0.1:3010/. The POST method requires `rune` and `nodeid` headers for authorization.

- `nodeid` is the same as `id (pubkey)` received from [getinfo](https://docs.corelightning.org/reference/lightning-getinfo).
- A new `rune` can be created via [createrune](https://docs.corelightning.org/reference/lightning-createrune) or the list of existing runes can be retrieved with [listrunes](https://docs.corelightning.org/reference/lightning-listrunes) command.

### cURL
Example curl command for POST will also require `rune` and `nodeid` headers like below:
    `curl -k -X POST 'https://127.0.0.1:3010/v1/getinfo' -H 'Rune: <node-rune>' -H 'Nodeid: <node-id>'`

With `-k` or `--insecure` option curl proceeds with the connection even if the SSL certificate cannot be verified.
This option should be used only when testing with self signed certificate.

### Swagger
<p float="left">
    <img src="./.github/screenshots/Swagger.png" width="200" alt="Swagger Dashboard" />
    <img src="./.github/screenshots/Swagger-auth.png" width="200" alt="Swagger Authorize" />
    <img src="./.github/screenshots/Swagger-list-methods.png" width="200" alt="Swagger GET List Methods" />
    <img src="./.github/screenshots/Swagger-rpc-method.png" width="200" alt="Swagger POST RPC Method" />
</p>

### Postman
<p float="left">
    <img src="./.github/screenshots/Postman.png" width="200" alt="Postman Headers">
    <img src="./.github/screenshots/Postman-with-body.png" width="200" alt="Postman with JSON body">
    <img src="./.github/screenshots/Postman-bkpr-plugin.png" width="200" alt="Postman bkpr plugin RPC">
</p>

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
