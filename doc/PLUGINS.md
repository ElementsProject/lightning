# Plugins

Plugins are a simple yet powerful way to extend the functionality
provided by c-lightning. They are subprocesses that are started by the
main `lightningd` daemon and can interact with `lightningd` in a
variety of ways:

 - **Command line option passthrough** allows plugins to register their
   own command line options that are exposed through `lightningd` so
   that only the main process needs to be configured.
 - **JSON-RPC command passthrough** adds a way for plugins to add their
   own commands to the JSON-RPC interface.
 - **Event stream subscriptions** provide plugins with a push-based
   notification mechanism about events from the `lightningd`.
 - **Hooks** are a primitive that allows plugins to be notified about
   internal events in `lightningd` and alter its behavior or inject
   custom behaviors.

A plugin may be written in any language, and communicates with
`lightningd` through the plugin's `stdin` and `stdout`. JSON-RPCv2 is
used as protocol on top of the two streams, with the plugin acting as
server and `lightningd` acting as client. The plugin file needs to be
executable (e.g. use `chmod a+x plugin_name`)

## A day in the life of a plugin

During startup of `lightningd` you can use the `--plugin=` option to
register one or more plugins that should be started. In case you wish
to start several plugins you have to use the `--plugin=` argument
once for each plugin (or `--plugin-dir` or place them in the default
plugin dirs, usually `/usr/local/libexec/c-lightning/plugins` and
`~/.lightningd/plugins`). An example call might look like:

```
lightningd --plugin=/path/to/plugin1 --plugin=path/to/plugin2
```

`lightningd` will run your plugins from the `--lightning-dir`/networkname, then
will write JSON-RPC requests to the plugin's `stdin` and
will read replies from its `stdout`. To initialize the plugin two RPC
methods are required:

 - `getmanifest` asks the plugin for command line options and JSON-RPC
   commands that should be passed through.  This can be run before
   `lightningd` checks that it is the sole user of the `lightning-dir`
   directory (for `--help`) so your plugin should not touch files at this
   point.
 - `init` is called after the command line options have been
   parsed and passes them through with the real values (if specified). This is also
   the signal that `lightningd`'s JSON-RPC over Unix Socket is now up
   and ready to receive incoming requests from the plugin.

Once those two methods were called `lightningd` will start passing
through incoming JSON-RPC commands that were registered and the plugin
may interact with `lightningd` using the JSON-RPC over Unix-Socket
interface.

### The `getmanifest` method

The `getmanifest` method is required for all plugins and will be
called on startup with optional parameters (in particular, it may have
`allow-deprecated-apis: false`, but you should accept, and ignore,
other parameters).  It MUST return a JSON object similar to this
example:

```json
{
  "options": [
    {
      "name": "greeting",
      "type": "string",
      "default": "World",
      "description": "What name should I call you?",
      "deprecated": false
    }
  ],
  "rpcmethods": [
    {
      "name": "hello",
      "usage": "[name]",
      "description": "Returns a personalized greeting for {greeting} (set via options)."
    },
    {
      "name": "gettime",
      "usage": "",
      "description": "Returns the current time in {timezone}",
      "long_description": "Returns the current time in the timezone that is given as the only parameter.\nThis description may be quite long and is allowed to span multiple lines.",
      "deprecated": false
    }
  ],
  "subscriptions": [
    "connect",
    "disconnect"
  ],
  "hooks": [
    { "name": "openchannel", "before": ["another_plugin"] },
    { "name": "htlc_accepted" }
  ],
  "featurebits": {
    "node": "D0000000",
    "channel": "D0000000",
    "init": "0E000000",
    "invoice": "00AD0000"
  },
  "notifications": [
    {
	  "method": "mycustomnotification"
	}
  ],
  "dynamic": true
}
```

The `options` will be added to the list of command line options that
`lightningd` accepts. The above will add a `--greeting` option with a
default value of `World` and the specified description. *Notice that
currently string, integers, bool, and flag options are supported.*

The `rpcmethods` are methods that will be exposed via `lightningd`'s
JSON-RPC over Unix-Socket interface, just like the builtin
commands. Any parameters given to the JSON-RPC calls will be passed
through verbatim. Notice that the `name`, `description` and `usage` fields
are mandatory, while the `long_description` can be omitted (it'll be
set to `description` if it was not provided). `usage` should surround optional
parameter names in `[]`.

`options` and `rpcmethods` can mark themselves `deprecated: true` if
you plan on removing them: this will disable them if the user sets
`allow-deprecated-apis` to false (which every developer should do,
right?).

The `dynamic` indicates if the plugin can be managed after `lightningd`
has been started. Critical plugins that should not be stopped should set it
to false.

If a `disable` member exists, the plugin will be disabled and the contents
of this member is the reason why.  This allows plugins to disable themselves
if they are not supported in this configuration.

The `featurebits` object allows the plugin to register featurebits that should be
announced in a number of places in [the protocol][bolt9]. They can be used to signal
support for custom protocol extensions to direct peers, remote nodes and in
invoices. Custom protocol extensions can be implemented for example using the
`sendcustommsg` method and the `custommsg` hook, or the `sendonion` method and
the `htlc_accepted` hook. The keys in the `featurebits` object are `node` for
features that should be announced via the `node_announcement` to all nodes in
the network, `init` for features that should be announced to direct peers
during the connection setup, `channel` for features which should apply to `channel_announcement`, and `invoice` for features that should be
announced to a potential sender of a payment in the invoice. The low range of
featurebits is reserved for standardize features, so please pick random, high
position bits for experiments. If you'd like to standardize your extension
please reach out to the [specification repository][spec] to get a featurebit
assigned.

The `notifications` array allows plugins to announce which custom
notifications they intend to send to `lightningd`. These custom
notifications can then be subscribed to by other plugins, allowing
them to communicate with each other via the existing publish-subscribe
mechanism and react to events that happen in other plugins, or collect
information based on the notification topics.

Plugins are free to register any `name` for their `rpcmethod` as long
as the name was not previously registered. This includes both built-in
methods, such as `help` and `getinfo`, as well as methods registered
by other plugins. If there is a conflict then `lightningd` will report
an error and exit.

#### Types of Options

There are currently four supported option 'types':
  - string: a string
  - bool: a boolean
  - int: parsed as a signed integer (64-bit)
  - flag: no-arg flag option. Is boolean under the hood. Defaults to false.

In addition, string and int types can specify `"multi": true` to indicate
they can be specified multiple times.  These will always be represented in
`init` as a (possibly empty) JSON array.

Nota bene: if a `flag` type option is not set, it will not appear
in the options set that is passed to the plugin.

Here's an example option set, as sent in response to `getmanifest`

```json
  "options": [
    {
      "name": "greeting",
      "type": "string",
      "default": "World",
      "description": "What name should I call you?"
    },
    {
      "name": "run-hot",
      "type": "flag",
      "default": None,  // defaults to false
      "description": "If set, overclocks plugin"
    },
    {
      "name": "is_online",
      "type": "bool",
      "default": false,
      "description": "Set to true if plugin can use network"
    },
    {
      "name": "service-port",
      "type": "int",
      "default": 6666,
      "description": "Port to use to connect to 3rd-party service"
    },
    {
      "name": "number",
      "type": "int",
      "default": 0,
      "description": "Another number to add",
	  "multi": true
    }
  ],
```

#### Custom notifications

The plugins may emit custom notifications for topics they have
announced during startup. The list of notification topics declared
during startup must include all topics that may be emitted, in order
to verify that all topics plugins subscribe to are also emitted by
some other plugin, and warn if a plugin subscribes to a non-existent
topic. In case a plugin emits notifications it has not announced the
notification will be ignored and not forwarded to subscribers.

When forwarding a custom notification `lightningd` will wrap the
payload of the notification in an object that contains metadata about
the notification. The following is an example of this
transformation. The first listing is the original notification emitted
by the `sender` plugin, while the second is the the notification as
received by the `receiver` plugin (both listings show the full
[JSON-RPC][jsonrpc-spec] notification to illustrate the wrapping).

```json
{
  "jsonrpc": "2.0",
  "method": "mycustomnotification",
  "params": {
    "key": "value",
	"message": "Hello fellow plugin!"
  }
}
```

is delivered as

```json
{
  "jsonrpc": "2.0",
  "method": "mycustomnotification",
  "params": {
    "origin": "sender",
    "payload": {
      "key": "value",
      "message": "Hello fellow plugin!"
    }
  }
}

```

The notification topic (`method` in the JSON-RPC message) must not
match one of the internal events in order to prevent breaking
subscribers that expect the existing notification format. Multiple
plugins are allowed to emit notifications for the same topics,
allowing things like metric aggregators where the aggregator
subscribes to a common topic and other plugins publish metrics as
notifications.

### The `init` method

The `init` method is required so that `lightningd` can pass back the
filled command line options and notify the plugin that `lightningd` is
now ready to receive JSON-RPC commands. The `params` of the call are a
simple JSON object containing the options:

```json
{
  "options": {
    "greeting": "World",
	"number": [0]
  },
  "configuration": {
    "lightning-dir": "/home/user/.lightning/testnet",
    "rpc-file": "lightning-rpc",
    "startup": true,
    "network": "testnet",
    "feature_set": {
        "init": "02aaa2",
        "node": "8000000002aaa2",
        "channel": "",
        "invoice": "028200"
    },
    "proxy": {
        "type": "ipv4",
        "address": "127.0.0.1",
        "port": 9050
    },
    "torv3-enabled": true,
    "use_proxy_always": false
  }
}
```

The plugin must respond to `init` calls.  The response should be a
valid JSON-RPC response to the `init`, but this is not currently
enforced.  If the response is an object containing `result` which
contains `disable` then the plugin will be disabled and the contents
of this member is the reason why.

The `startup` field allows a plugin to detect if it was started at
`lightningd` startup (true), or at runtime (false).

## JSON-RPC passthrough

Plugins may register their own JSON-RPC methods that are exposed
through the JSON-RPC provided by `lightningd`. This provides users
with a single interface to interact with, while allowing the addition
of custom methods without having to modify the daemon itself.

JSON-RPC methods are registered as part of the `getmanifest`
result. Each registered method must provide a `name` and a
`description`. An optional `long_description` may also be
provided. This information is then added to the internal dispatch
table, and used to return the help text when using `lightning-cli
help`, and the methods can be called using the `name`.

For example the above `getmanifest` result will register two methods,
called `hello` and `gettime`:

```json
  ...
  "rpcmethods": [
    {
      "name": "hello",
      "usage": "[name]",
      "description": "Returns a personalized greeting for {greeting} (set via options)."
    },
    {
      "name": "gettime",
      "description": "Returns the current time in {timezone}",
      "usage": "",
      "long_description": "Returns the current time in the timezone that is given as the only parameter.\nThis description may be quite long and is allowed to span multiple lines."
    }
  ],
  ...
```

The RPC call will be passed through unmodified, with the exception of
the JSON-RPC call `id`, which is internally remapped to a unique
integer instead, in order to avoid collisions. When passing the result
back the `id` field is restored to its original value.

Note that if your `result` for an RPC call includes `"format-hint":
"simple"`, then `lightning-cli` will default to printing your output
in "human-readable" flat form.

## Event notifications

Event notifications allow a plugin to subscribe to events in
`lightningd`. `lightningd` will then send a push notification if an
event matching the subscription occurred. A notification is defined in
the JSON-RPC [specification][jsonrpc-spec] as an RPC call that does
not include an `id` parameter:

> A Notification is a Request object without an "id" member. A Request
> object that is a Notification signifies the Client's lack of
> interest in the corresponding Response object, and as such no
> Response object needs to be returned to the client. The Server MUST
> NOT reply to a Notification, including those that are within a batch
> request.
>
> Notifications are not confirmable by definition, since they do not
> have a Response object to be returned. As such, the Client would not
> be aware of any errors (like e.g. "Invalid params","Internal
> error").

Plugins subscribe by returning an array of subscriptions as part of
the `getmanifest` response. The result for the `getmanifest` call
above for example subscribes to the two topics `connect` and
`disconnect`. The topics that are currently defined and the
corresponding payloads are listed below.


### `channel_opened`

A notification for topic `channel_opened` is sent if a peer successfully
funded a channel with us. It contains the peer id, the funding amount
(in millisatoshis), the funding transaction id, and a boolean indicating
if the funding transaction has been included into a block.

```json
{
  "channel_opened": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "funding_satoshis": "100000000msat",
    "funding_txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    "funding_locked": false
  }
}
```

### `channel_open_failed`

A notification to indicate that a channel open attempt has been unsuccessful.
Useful for cleaning up state for a v2 channel open attempt. See
`plugins/funder.c` for an example of how to use this.

```json
{
  "channel_open_failed": {
    "channel_id": "a2d0851832f0e30a0cf...",
  }
}
```

### `channel_state_changed`

A notification for topic `channel_state_changed` is sent every time a channel
changes its state. The notification includes the `peer_id` and `channel_id`, the
old and new channel states, the type of `cause` and a `message`.

```json
{
    "channel_state_changed": {
        "peer_id": "03bc9337c7a28bb784d67742ebedd30a93bacdf7e4ca16436ef3798000242b2251",
        "channel_id": "a2d0851832f0e30a0cf778a826d72f077ca86b69f72677e0267f23f63a0599b4",
        "short_channel_id" : "561820x1020x1",
        "old_state": "CHANNELD_NORMAL",
        "new_state": "CHANNELD_SHUTTING_DOWN",
        "cause" : "remote",
        "message" : "Peer closes channel"
    }
}
```

A `cause` can have the following values:
 - "unknown"   Anything other than the reasons below. Should not happen.
 - "local"     Unconscious internal reasons, e.g. dev fail of a channel.
 - "user"      The operator or a plugin opened or closed a channel by intention.
 - "remote"    The remote closed or funded a channel with us by intention.
 - "protocol"  We need to close a channel because of bad signatures and such.
 - "onchain"   A channel was closed onchain, while we were offline.

Most state changes are caused subsequentially for a prior state change, e.g.
"CLOSINGD_COMPLETE" is followed by "FUNDING_SPEND_SEEN". Because of this, the
`cause` reflects the last known reason in terms of local or remote user
interaction, protocol reasons, etc. More specifically, a `new_state`
"FUNDING_SPEND_SEEN" will likely _not_ have "onchain" as a `cause` but some
value such as "REMOTE" or "LOCAL" depending on who initiated the closing of a
channel.

Note: If the channel is not closed or being closed yet, the `cause` will reflect
which side "remote" or "local" opened the channel.

Note: If the cause is "onchain" this was very likely a conscious decision of the
remote peer, but we have been offline.

### `connect`

A notification for topic `connect` is sent every time a new connection
to a peer is established. `direction` is either `"in"` or `"out"`.

```json
{
  "id": "02f6725f9c1c40333b67faea92fd211c183050f28df32cac3f9d69685fe9665432",
  "direction": "in",
  "address": "1.2.3.4:1234"
}
```

### `disconnect`

A notification for topic `disconnect` is sent every time a connection
to a peer was lost.

```json
{
  "id": "02f6725f9c1c40333b67faea92fd211c183050f28df32cac3f9d69685fe9665432"
}
```

### `invoice_payment`

A notification for topic `invoice_payment` is sent every time an invoice is paid.

```json
{
  "invoice_payment": {
    "label": "unique-label-for-invoice",
    "preimage": "0000000000000000000000000000000000000000000000000000000000000000",
    "msat": "10000msat"
  }
}

```
### `invoice_creation`

A notification for topic `invoice_creation` is sent every time an invoice is created.

```json
{
  "invoice_creation": {
    "label": "unique-label-for-invoice",
    "preimage": "0000000000000000000000000000000000000000000000000000000000000000",
    "msat": "10000msat"
  }
}
```

### `warning`

A notification for topic `warning` is sent every time a new `BROKEN`
/`UNUSUAL` level(in plugins, we use `error`/`warn`) log generated,
which means an unusual/borken thing happens, such as channel failed,
message resolving failed...

```json
{
  "warning": {
    "level": "warn",
    "time": "1559743608.565342521",
    "source": "lightningd(17652): 0821f80652fb840239df8dc99205792bba2e559a05469915804c08420230e23c7c chan #7854:",
    "log": "Peer permanent failure in CHANNELD_NORMAL: lightning_channeld: sent ERROR bad reestablish dataloss msg"
  }
}
```
1. `level` is `warn` or `error`: `warn` means something seems bad happened
 and it's under control, but we'd better check it; `error` means something
extremely bad is out of control, and it may lead to crash;
2. `time` is the second since epoch;
3. `source` means where the event happened, it may have the following
forms:
`<node_id> chan #<db_id_of_channel>:`,`lightningd(<lightningd_pid>):`,
`plugin-<plugin_name>:`, `<daemon_name>(<daemon_pid>):`, `jsonrpc:`,
`jcon fd <error_fd_to_jsonrpc>:`, `plugin-manager`;
4. `log` is the context of the original log entry.

### `forward_event`

A notification for topic `forward_event` is sent every time the status
of a forward payment is set. The json format is same as the API
`listforwards`.

```json
{
  "forward_event": {
    "payment_hash": "f5a6a059a25d1e329d9b094aeeec8c2191ca037d3f5b0662e21ae850debe8ea2",
    "in_channel": "103x2x1",
    "out_channel": "103x1x1",
    "in_msatoshi": 100001001,
    "in_msat": "100001001msat",
    "out_msatoshi": 100000000,
    "out_msat": "100000000msat",
    "fee": 1001,
    "fee_msat": "1001msat",
    "status": "settled",
    "received_time": 1560696342.368,
    "resolved_time": 1560696342.556
  }
}
```
or

```json
{
  "forward_event": {
    "payment_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "in_channel": "103x2x1",
    "out_channel": "110x1x0",
    "in_msatoshi": 100001001,
    "in_msat": "100001001msat",
    "out_msatoshi": 100000000,
    "out_msat": "100000000msat",
    "fee": 1001,
    "fee_msat": "1001msat",
    "status": "local_failed",
    "failcode": 16392,
    "failreason": "WIRE_PERMANENT_CHANNEL_FAILURE",
    "received_time": 1560696343.052
  }
}

```
 - The status includes `offered`, `settled`, `failed` and `local_failed`,
   and they are all string type in json.
   - When the forward payment is valid for us, we'll set `offered`
     and send the forward payment to next hop to resolve;
   - When the payment forwarded by us gets paid eventually, the forward
     payment will change the status from `offered` to `settled`;
   - If payment fails locally(like failing to resolve locally) or the
     corresponding htlc with next hop fails(like htlc timeout), we will
     set the status as `local_failed`. `local_failed` may be set before
     setting `offered` or after setting `offered`. In fact, from the
     time we receive the htlc of the previous hop, all we can know the
     cause of the failure is treated as `local_failed`. `local_failed`
     only occuors locally or happens in the htlc between us and next hop;
     - If `local_failed` is set before `offered`, this
       means we just received htlc from the previous hop and haven't
       generate htlc for next hop. In this case, the json of `forward_event`
       sets the fields of `out_msatoshi`, `out_msat`,`fee` and `out_channel`
       as 0;
       - Note: In fact, for this case we may be not sure if this incoming
         htlc represents a pay to us or a payment we need to forward.
         We just simply treat all incoming failed to resolve as
         `local_failed`.
     - Only in `local_failed` case, json includes `failcode` and
       `failreason` fields;
   - `failed` means the payment forwarded by us fails in the
     latter hops, and the failure isn't related to us, so we aren't
     accessed to the fail reason. `failed` must be set after
     `offered`.
     - `failed` case doesn't include `failcode` and `failreason`
       fields;
 - `received_time` means when we received the htlc of this payment from
   the previous peer. It will be contained into all status case;
 - `resolved_time` means when the htlc of this payment between us and the
   next peer was resolved. The resolved result may success or fail, so
   only `settled` and `failed` case contain `resolved_time`;
 - The `failcode` and `failreason` are defined in [BOLT 4][bolt4-failure-codes].

### `sendpay_success`

A notification for topic `sendpay_success` is sent every time a sendpay
succeeds (with `complete` status). The json is the same as the return value of
the commands `sendpay`/`waitsendpay` when these commands succeed.

```json
{
  "sendpay_success": {
    "id": 1,
    "payment_hash": "5c85bf402b87d4860f4a728e2e58a2418bda92cd7aea0ce494f11670cfbfb206",
    "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
    "msatoshi": 100000000,
    "amount_msat": "100000000msat",
    "msatoshi_sent": 100001001,
    "amount_sent_msat": "100001001msat",
    "created_at": 1561390572,
    "status": "complete",
    "payment_preimage": "9540d98095fd7f37687ebb7759e733934234d4f934e34433d4998a37de3733ee"
  }
}
```
`sendpay` doesn't wait for the result of sendpay and `waitsendpay`
returns the result of sendpay in specified time or timeout, but
`sendpay_success` will always return the result anytime when sendpay
successes if is was subscribed.

### `sendpay_failure`

A notification for topic `sendpay_failure` is sent every time a sendpay
completes with `failed` status. The JSON is same as the return value of
the commands `sendpay`/`waitsendpay` when these commands fail.

```json
{
  "sendpay_failure": {
    "code": 204,
    "message": "failed: WIRE_UNKNOWN_NEXT_PEER (reply from remote)",
    "data": {
      "id": 2,
      "payment_hash": "9036e3bdbd2515f1e653cb9f22f8e4c49b73aa2c36e937c926f43e33b8db8851",
      "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
      "msatoshi": 100000000,
      "amount_msat": "100000000msat",
      "msatoshi_sent": 100001001,
      "amount_sent_msat": "100001001msat",
      "created_at": 1561395134,
      "status": "failed",
      "erring_index": 1,
      "failcode": 16394,
      "failcodename": "WIRE_UNKNOWN_NEXT_PEER",
      "erring_node": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "erring_channel": "103x2x1",
      "erring_direction": 0
    }
  }
}
```
`sendpay` doesn't wait for the result of sendpay and `waitsendpay`
returns the result of sendpay in specified time or timeout, but
`sendpay_failure` will always return the result anytime when sendpay
fails if is was subscribed.


### `coin_movement`

A notification for topic `coin_movement` is sent to record the
movement of coins.  It is only triggered by finalized ledger updates,
i.e. only definitively resolved HTLCs or confirmed bitcoin transactions.

```json
{
	"coin_movement": {
		"version":1,
		"node_id":"03a7103a2322b811f7369cbb27fb213d30bbc0b012082fed3cad7e4498da2dc56b",
		"movement_idx":0,
		"type":"chain_mvt",
		"account_id":"wallet",
		"txid":"0159693d8f3876b4def468b208712c630309381e9d106a9836fa0a9571a28722", // (`chain_mvt` type only, mandatory)
		"utxo_txid":"0159693d8f3876b4def468b208712c630309381e9d106a9836fa0a9571a28722", // (`chain_mvt` type only, optional)
		"vout":1, // (`chain_mvt` type only, optional)
		"payment_hash": "xxx", // (either type, optional on `chain_mvt`)
		"part_id": 0, // (`channel_mvt` type only, mandatory)
		"credit":"2000000000msat",
		"debit":"0msat",
		"tag":"deposit",
		"blockheight":102, // (`channel_mvt` type only. may be null)
		"timestamp":1585948198,
		"coin_type":"bc"
	}
}
```

`version` indicates which version of the coin movement data struct this
notification adheres to.

`node_id` specifies the node issuing the coin movement.

`movement_idx` is an increment-only counter for coin moves emitted by this node.

`type` marks the underlying mechanism which moved these coins. There are two
'types' of `coin_movements`:
  - `channel_mvt`s, which occur as a result of htlcs being resolved and,
  - `chain_mvt`s, which occur as a result of bitcoin txs being mined.

`account_id` is the name of this account. The node's wallet is named 'wallet',
all channel funds' account are the channel id.

`txid` is the transaction id of the bitcoin transaction that triggered this
ledger event. `utxo_txid` and `vout` identify the bitcoin output which triggered
this notification. (`chain_mvt` only) In most cases, the `utxo_txid` will be the
same as the `txid`, except for `spend_track` notficiations.  Notifications tagged
`chain_fees` and `journal_entry` do not have a `utxo_txid` as they're not
represented in the utxo set.

`payment_hash` is the hash of the preimage used to move this payment. Only
present for HTLC mediated moves (both `chain_mvt` and `channel_mvt`)
A `chain_mvt` will have a `payment_hash` iff it's recording an htlc that was
fulfilled onchain.

`part_id` is an identifier for parts of a multi-part payment. useful for
aggregating payments for an invoice or to indicate why a payment hash appears
multiple times. `channel_mvt` only

`credit` and `debit` are millisatoshi denominated amounts of the fund movement. A
'credit' is funds deposited into an account; a `debit` is funds withdrawn.


`tag` is a movement descriptor. Current tags are as follows:
 - `deposit`: funds deposited
 - `withdrawal`: funds withdrawn
 - `chain_fees`: funds paid for onchain fees. `chain_mvt` only
 - `penalty`: funds paid or gained from a penalty tx. `chain_mvt` only
 - `invoice`: funds paid to or recieved from an invoice. `channel_mvt` only
 - `routed`: funds routed through this node. `channel_mvt` only
 - `journal_entry`: a balance reconciliation event, typically triggered
                    by a penalty tx onchain. `chain_mvt` only
 - `onchain_htlc`: funds moved via an htlc onchain. `chain_mvt` only
 - `pushed`: funds pushed to peer. `channel_mvt` only.
 - `spend_track`:  informational notification about a wallet utxo spend. `chain_mvt` only.

`blockheight` is the block the txid is included in. `chain_mvt` only. In the
case that an output is considered dust, c-lightning does not track its return to
our wallet. In those cases, the blockheight will be `null`, as they're recorded
before confirmation.

The `timestamp` is seconds since Unix epoch of the node's machine time
at the time lightningd broadcasts the notification.

`coin_type` is the BIP173 name for the coin which moved.

### `openchannel_peer_sigs`

When opening a channel with a peer using the collaborative transaction protocol
(`opt_dual_fund`), this notification is fired when the peer sends us their funding
transaction signatures, `tx_signatures`. We update the in-progress PSBT and return it
here, with the peer's signatures attached.

```json
{
  "openchannel_peer_sigs": {
    "channel_id": "252d1b0a1e5789...",
    "signed_psbt": "cHNidP8BAKgCAAAAAQ+y+61AQAAAAD9////AzbkHAAAAAAAFgAUwsyrFxwqW+natS7EG4JYYwJMVGZQwwAAAAAAACIAIKYE2s4YZ+RON6BB5lYQESHR9cA7hDm6/maYtTzSLA0hUMMAAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzWYAAAAAAQDfAgAAAAABARtaSZufCbC+P+/G23XVaQ8mDwZQFW1vlCsCYhLbmVrpAAAAAAD+////AvJs5ykBAAAAFgAUT6ORgb3CgFsbwSOzNLzF7jQS5s+AhB4AAAAAABepFNi369DMyAJmqX2agouvGHcDKsZkhwJHMEQCIHELIyqrqlwRjyzquEPvqiorzL2hrvdu9EBxsqppeIKiAiBykC6De/PDElnqWw49y2vTqauSJIVBgGtSc+vq5BQd+gEhAg0f8WITWvA8o4grxNKfgdrNDncqreMLeRFiteUlne+GZQAAAAEBIICEHgAAAAAAF6kU2Lfr0MzIAmapfZqCi68YdwMqxmSHAQcXFgAUAfrZCrzWZpfiWSFkci3kqV6+4WUBCGsCRzBEAiBF31wbNWECsJ0DrPel2inWla2hYpCgaxeVgPAvFEOT2AIgWiFWN0hvUaK6kEnXhED50wQ2fBqnobsRhoy1iDDKXE0BIQPXRURck2JmXyLg2W6edm8nPzJg3qOcina/oF3SaE3czwz8CWxpZ2h0bmluZwEIexhVcpJl8ugM/AlsaWdodG5pbmcCAgABAAz8CWxpZ2h0bmluZwEIR7FutlQgkSoADPwJbGlnaHRuaW5nAQhYT+HjxFBqeAAM/AlsaWdodG5pbmcBCOpQ5iiTTNQEAA=="
  }
}
```

## Hooks

Hooks allow a plugin to define custom behavior for `lightningd`
without having to modify the c-lightning source code itself. A plugin
declares that it'd like to be consulted on what to do next for certain
events in the daemon. A hook can then decide how `lightningd` should
react to the given event.

When hooks are registered, they can optionally specify "before" and
"after" arrays of plugin names, which control what order they will be
called in.  If a plugin name is unknown, it is ignored, otherwise if the
hook calls cannot be ordered to satisfy the specifications of all
plugin hooks, the plugin registration will fail.

The call semantics of the hooks, i.e., when and how hooks are called, depend
on the hook type. Most hooks are currently set to `single`-mode. In this mode
only a single plugin can register the hook, and that plugin will get called
for each event of that type. If a second plugin attempts to register the hook
it gets killed and a corresponding log entry will be added to the logs.

In `chain`-mode multiple plugins can register for the hook type and
they are called in any order they are loaded (i.e. cmdline order
first, configuration order file second: though note that the order of
plugin directories is implementation-dependent), overriden only by
`before` and `after` requirements the plugin's hook registrations specify.
Each plugin can then handle the event or defer by returning a
`continue` result like the following:

```json
{
  "result": "continue"
}
```

The remainder of the response is ignored and if there are any more plugins
that have registered the hook the next one gets called. If there are no more
plugins then the internal handling is resumed as if no hook had been
called. Any other result returned by a plugin is considered an exit from the
chain. Upon exit no more plugin hooks are called for the current event, and
the result is executed. Unless otherwise stated all hooks are `single`-mode.

Hooks and notifications are very similar, however there are a few
key differences:

 - Notifications are asynchronous, i.e., `lightningd` will send the
   notifications but not wait for the plugin to process them. Hooks on
   the other hand are synchronous, `lightningd` cannot finish
   processing the event until the plugin has returned.
 - Any number of plugins can subscribe to a notification topic and get
   notified in parallel, however only one plugin may register for
   `single`-mode hook types, and in all cases only one plugin may return a
   non-`continue` response. This avoids having multiple contradictory
   responses.

Hooks are considered to be an advanced feature due to the fact that
`lightningd` relies on the plugin to tell it what to do next. Use them
carefully, and make sure your plugins always return a valid response
to any hook invocation.

As a convention, for all hooks, returning the object
`{ "result" : "continue" }` results in `lightningd` behaving exactly as if
no plugin is registered on the hook.

### `peer_connected`

This hook is called whenever a peer has connected and successfully completed
the cryptographic handshake. The parameters have the following structure:

```json
{
  "peer": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
	"direction": "in",
    "addr": "34.239.230.56:9735",
    "features": ""
  }
}
```

The hook is sparse on information, since the plugin can use the JSON-RPC
`listpeers` command to get additional details should they be required.
`direction` is either `"in"` or `"out"`. The `addr` field shows the address
that we are connected to ourselves, not the gossiped list of known
addresses. In particular this means that the port for incoming connections is
an ephemeral port, that may not be available for reconnections.

The returned result must contain a `result` member which is either
the string `disconnect` or `continue`.  If `disconnect` and
there's a member `error_message`, that member is sent to the peer
before disconnection.

Note that `peer_connected` is a chained hook. The first plugin that decides to
`disconnect` with or without an `error_message` will lead to the subsequent
plugins not being called anymore.

### `commitment_revocation`

This hook is called whenever a channel state is updated, and the old state was
revoked. State updates in Lightning consist of the following steps:

 1. Proposal of a new state commitment in the form of a commitment transaction
 2. Exchange of signatures for the agreed upon commitment transaction
 3. Verification that the signatures match the commitment transaction
 4. Exchange of revocation secrets that could be used to penalize an eventual misbehaving party

The `commitment_revocation` hook is used to inform the plugin about the state
transition being completed, and deliver the penalty transaction. The penalty
transaction could then be sent to a watchtower that automaticaly reacts in
case one party attempts to settle using a revoked commitment.

The payload consists of the following information:

```json
{
	"commitment_txid": "58eea2cf538cfed79f4d6b809b920b40bb6b35962c4bb4cc81f5550a7728ab05",
	"penalty_tx": "02000000000101...ac00000000"
}
```

Notice that the `commitment_txid` could also be extracted from the sole input
of the `penalty_tx`, however it is enclosed so plugins don't have to include
the logic to parse transactions.

Not included are the `htlc_success` and `htlc_failure` transactions that
may also be spending `commitment_tx` outputs. This is because these
transactions are much more dynamic and have a predictable timeout, allowing
wallets to ensure a quick checkin when the CLTV of the HTLC is about to
expire.

The `commitment_revocation` hook is a chained hook, i.e., multiple plugins can
register it, and they will be called in the order they were registered in.
Plugins should always return `{"result": "continue"}`, otherwise subsequent
hook subscribers would not get called.

### `db_write`

This hook is called whenever a change is about to be committed to the database.
It is currently extremely restricted:

1. a plugin registering for this hook should not perform anything that may cause
   a db operation in response (pretty much, anything but logging).
2. a plugin registering for this hook should not register for other hooks or
   commands, as these may become intermingled and break rule #1.
3. the hook will be called before your plugin is initialized!

This hook, unlike all the other hooks, is also strongly synchronous:
`lightningd` will stop almost all the other processing until this
hook responds.

```json
{
  "data_version": 42,
  "writes": [
    "PRAGMA foreign_keys = ON"
  ]
}
```

This hook is intended for creating continuous backups.
The intent is that your backup plugin maintains three
pieces of information (possibly in separate files):
(1) a snapshot of the database, (2) a log of database queries
that will bring that snapshot up-to-date, and (3) the previous
`data_version`.

`data_version` is an unsigned 32-bit number that will always
increment by 1 each time `db_write` is called.
Note that this will wrap around on the limit of 32-bit numbers.

`writes` is an array of strings, each string being a database query
that modifies the database.
If the `data_version` above is validated correctly, then you can
simply append this to the log of database queries.

Your plugin **MUST** validate the `data_version`.
It **MUST** keep track of the previous `data_version` it got,
and:

1. If the new `data_version` is ***exactly*** one higher than
   the previous, then this is the ideal case and nothing bad
   happened and we should save this and continue.
2. If the new `data_version` is ***exactly*** the same value
   as the previous, then the previous set of queries was not
   committed.
   Your plugin **MAY** overwrite the previous set of queries with
   the current set, or it **MAY** overwrite its entire backup
   with a new snapshot of the database and the current `writes`
   array (treating this case as if `data_version` were two or
   more higher than the previous).
3. If the new `data_version` is ***less than*** the previous,
   your plugin **MUST** halt and catch fire, and have the
   operator inspect what exactly happend here.
4. Otherwise, some queries were lost and your plugin **SHOULD**
   recover by creating a new snapshot of the database: copy the
   database file, back up the given `writes` array, then delete
   (or atomically `rename` if in a POSIX filesystem) the previous
   backups of the database and SQL statements, or you **MAY**
   fail the hook to abort `lightningd`.

The "rolling up" of the database could be done periodically as well
if the log of SQL statements has grown large.

Any response other than `{"result": "continue"}` will cause lightningd
to error without
committing to the database!
This is the expected way to halt and catch fire.

`db_write` is a parallel-chained hook, i.e., multiple plugins can
register it, and all of them will be invoked simultaneously without
regard for order of registration.
The hook is considered handled if all registered plugins return
`{"result": "continue"}`.
If any plugin returns anything else, `lightningd` will error without
committing to the database.

### `invoice_payment`

This hook is called whenever a valid payment for an unpaid invoice has arrived.

```json
{
  "payment": {
    "label": "unique-label-for-invoice",
    "preimage": "0000000000000000000000000000000000000000000000000000000000000000",
    "msat": "10000msat"
  }
}
```

The hook is deliberately sparse, since the plugin can use the JSON-RPC
`listinvoices` command to get additional details about this invoice.
It can return a `failure_message` field as defined for final
nodes in [BOLT 4][bolt4-failure-messages], a `result` field with the string
`reject` to fail it with `incorrect_or_unknown_payment_details`, or a
`result` field with the string `continue` to accept the payment.


### `openchannel`

This hook is called whenever a remote peer tries to fund a channel to us using
the v1 protocol, and it has passed basic sanity checks:

```json
{
  "openchannel": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "funding_satoshis": "100000000msat",
    "push_msat": "0msat",
    "dust_limit_satoshis": "546000msat",
    "max_htlc_value_in_flight_msat": "18446744073709551615msat",
    "channel_reserve_satoshis": "1000000msat",
    "htlc_minimum_msat": "0msat",
    "feerate_per_kw": 7500,
    "to_self_delay": 5,
    "max_accepted_htlcs": 483,
    "channel_flags": 1
  }
}
```

There may be additional fields, including `shutdown_scriptpubkey` and
a hex-string.  You can see the definitions of these fields in [BOLT 2's description of the open_channel message][bolt2-open-channel].

The returned result must contain a `result` member which is either
the string `reject` or `continue`.  If `reject` and
there's a member `error_message`, that member is sent to the peer
before disconnection.

For a 'continue'd result, you can also include a `close_to` address,
which will be used as the output address for a mutual close transaction.

e.g.

```json
{
    "result": "continue",
    "close_to": "bc1qlq8srqnz64wgklmqvurv7qnr4rvtq2u96hhfg2"
}
```

Note that `close_to` must be a valid address for the current chain,
an invalid address will cause the node to exit with an error.

Note that `openchannel` is a chained hook. Therefore `close_to` will only be
evaluated for the first plugin that sets it. If more than one plugin tries to
set a `close_to` address an error will be logged.

### `openchannel2`

This hook is called whenever a remote peer tries to fund a channel to us using
the v2 protocol, and it has passed basic sanity checks:

```json
{
  "openchannel2": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
    "their_funding": "100000000msat",
    "dust_limit_satoshis": "546000msat",
    "max_htlc_value_in_flight_msat": "18446744073709551615msat",
    "htlc_minimum_msat": "0msat",
    "funding_feerate_per_kw": 7500,
    "commitment_feerate_per_kw": 7500,
    "feerate_our_max": 10000,
    "feerate_our_min": 253,
    "to_self_delay": 5,
    "max_accepted_htlcs": 483,
    "channel_flags": 1
    "locktime": 2453,
    "channel_max_msat": "16777215000msat"
  }
}
```

There may be additional fields, such as `shutdown_scriptpubkey`.  You can
see the definitions of these fields in [BOLT 2's description of the open_channel message][bolt2-open-channel].

The returned result must contain a `result` member which is either
the string `reject` or `continue`.  If `reject` and
there's a member `error_message`, that member is sent to the peer
before disconnection.

For a 'continue'd result, you can also include a `close_to` address,
which will be used as the output address for a mutual close transaction; you
can include a `psbt` and an `our_funding_msat` to contribute funds,
inputs and outputs to this channel open.

Note that, like `openchannel_init` RPC call, the `our_funding_msat` amount
must NOT be accounted for in any supplied output. Change, however, should be
included and should use the `funding_feerate_per_kw` to calculate.

See `plugins/funder.c` for an example of how to use this hook
to contribute funds to a channel open.

e.g.

```json
{
    "result": "continue",
    "close_to": "bc1qlq8srqnz64wgklmqvurv7qnr4rvtq2u96hhfg2"
    "psbt": "cHNidP8BADMCAAAAAQ+yBipSVZrrw28Oed52hTw3N7t0HbIyZhFdcZRH3+61AQAAAAD9////AGYAAAAAAQDfAgAAAAABARtaSZufCbC+P+/G23XVaQ8mDwZQFW1vlCsCYhLbmVrpAAAAAAD+////AvJs5ykBAAAAFgAUT6ORgb3CgFsbwSOzNLzF7jQS5s+AhB4AAAAAABepFNi369DMyAJmqX2agouvGHcDKsZkhwJHMEQCIHELIyqrqlwRjyzquEPvqiorzL2hrvdu9EBxsqppeIKiAiBykC6De/PDElnqWw49y2vTqauSJIVBgGtSc+vq5BQd+gEhAg0f8WITWvA8o4grxNKfgdrNDncqreMLeRFiteUlne+GZQAAAAEBIICEHgAAAAAAF6kU2Lfr0MzIAmapfZqCi68YdwMqxmSHAQQWABQB+tkKvNZml+JZIWRyLeSpXr7hZQz8CWxpZ2h0bmluZwEIexhVcpJl8ugM/AlsaWdodG5pbmcCAgABAA==",
    "our_funding_msat": "39999000msat"
}
```

Note that `close_to` must be a valid address for the current chain,
an invalid address will cause the node to exit with an error.

Note that `openchannel` is a chained hook. Therefore `close_to` will only be
evaluated for the first plugin that sets it. If more than one plugin tries to
set a `close_to` address an error will be logged.


### `openchannel2_changed`

This hook is called when we received updates to the funding transaction
from the peer.

```json
{
	"openchannel2_changed": {
		"channel_id": "252d1b0a1e57895e841...",
		"psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
	}
}
```

In return, we expect a `result` indicated to `continue` and an updated `psbt`.
If we have no updates to contribute, return the passed in PSBT. Once no
changes to the PSBT are made on either side, the transaction construction
negotation will end and commitment transactions will be exchanged.

#### Expected Return
```json
{
	"result": "continue",
	"psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
}
```

See `plugins/funder.c` for an example of how to use this hook
to continue a v2 channel open.


### `openchannel2_sign`

This hook is called after we've gotten the commitment transactions for a
channel open. It expects psbt to be returned which contains signatures
for our inputs to the funding transaction.

```json
{
	"openchannel2_sign": {
		"channel_id": "252d1b0a1e57895e841...",
		"psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
	}
}
```

In return, we expect a `result` indicated to `continue` and an partially
signed `psbt`.

If we have no inputs to sign, return the passed in PSBT. Once we have also
received the signatures from the peer, the funding transaction will be
broadcast.

#### Expected Return
```json
{
	"result": "continue",
	"psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
}
```

See `plugins/funder.c` for an example of how to use this hook
to sign a funding transaction.


### `rbf_channel`

Similar to `openchannel2`, the `rbf_channel` hook is called when a peer
requests an RBF for a channel funding transaction.

```json
{
  "rbf_channel": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
    "their_funding": "100000000msat",
    "funding_feerate_per_kw": 7500,
    "feerate_our_max": 10000,
    "feerate_our_min": 253,
    "channel_max_msat": "16777215000msat",
    "locktime": 2453
  }
}
```

The returned result must contain a `result` member which is either
the string `reject` or `continue`.  If `reject` and
there's a member `error_message`, that member is sent to the peer
before disconnection.

For a 'continue'd result, you can include a `psbt` and an
`our_funding_msat` to contribute funds, inputs and outputs to
this channel open.

Note that, like the `openchannel_init` RPC call, the `our_funding_msat`
amount must NOT be accounted for in any supplied output. Change,
however, should be included and should use the `funding_feerate_per_kw`
to calculate.

#### Return

```json
{
    "result": "continue",
    "psbt": "cHNidP8BADMCAAAAAQ+yBipSVZrrw28Oed52hTw3N7t0HbIyZhFdcZRH3+61AQAAAAD9////AGYAAAAAAQDfAgAAAAABARtaSZufCbC+P+/G23XVaQ8mDwZQFW1vlCsCYhLbmVrpAAAAAAD+////AvJs5ykBAAAAFgAUT6ORgb3CgFsbwSOzNLzF7jQS5s+AhB4AAAAAABepFNi369DMyAJmqX2agouvGHcDKsZkhwJHMEQCIHELIyqrqlwRjyzquEPvqiorzL2hrvdu9EBxsqppeIKiAiBykC6De/PDElnqWw49y2vTqauSJIVBgGtSc+vq5BQd+gEhAg0f8WITWvA8o4grxNKfgdrNDncqreMLeRFiteUlne+GZQAAAAEBIICEHgAAAAAAF6kU2Lfr0MzIAmapfZqCi68YdwMqxmSHAQQWABQB+tkKvNZml+JZIWRyLeSpXr7hZQz8CWxpZ2h0bmluZwEIexhVcpJl8ugM/AlsaWdodG5pbmcCAgABAA==",
    "our_funding_msat": "39999000msat"
}
```



### `htlc_accepted`

The `htlc_accepted` hook is called whenever an incoming HTLC is accepted, and
its result determines how `lightningd` should treat that HTLC.

The payload of the hook call has the following format:

```json
{
  "onion": {
    "payload": "",
    "type": "legacy",
    "short_channel_id": "1x2x3",
    "forward_amount": "42msat",
    "outgoing_cltv_value": 500014,
    "shared_secret": "0000000000000000000000000000000000000000000000000000000000000000",
    "next_onion": "[1365bytes of serialized onion]"
  },
  "htlc": {
    "amount": "43msat",
    "cltv_expiry": 500028,
    "cltv_expiry_relative": 10,
    "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

For detailed information about each field please refer to [BOLT 04 of the specification][bolt4], the following is just a brief summary:

 - `onion`:
   - `payload` contains the unparsed payload that was sent to us from the
   sender of the payment.
   - `type` is `legacy` for realm 0 payments, `tlv` for realm > 1.
   - `short_channel_id` determines the channel that the sender is hinting
       should be used next.  Not present if we're the final destination.
   - `forward_amount` is the amount we should be forwarding to the next hop,
       and should match the incoming funds in case we are the recipient.
   - `outgoing_cltv_value` determines what the CLTV value for the HTLC that we
       forward to the next hop should be.
   - `total_msat` specifies the total amount to pay, if present.
   - `payment_secret` specifies the payment secret (which the payer should have obtained from the invoice), if present.
   - `next_onion` is the fully processed onion that we should be sending to the
     next hop as part of the outgoing HTLC. Processed in this case means that we
     took the incoming onion, decrypted it, extracted the payload destined for
     us, and serialized the resulting onion again.
   - `shared_secret` is the shared secret we used to decrypt the incoming
     onion. It is shared with the sender that constructed the onion.
 - `htlc`:
   - `amount` is the amount that we received with the HTLC. This amount minus
     the `forward_amount` is the fee that will stay with us.
   - `cltv_expiry` determines when the HTLC reverts back to the
     sender. `cltv_expiry` minus `outgoing_cltv_expiry` should be equal or
     larger than our `cltv_delta` setting.
   - `cltv_expiry_relative` hints how much time we still have to claim the
     HTLC. It is the `cltv_expiry` minus the current `blockheight` and is
     passed along mainly to avoid the plugin having to look up the current
     blockheight.
   - `payment_hash` is the hash whose `payment_preimage` will unlock the funds
     and allow us to claim the HTLC.

The hook response must have one of the following formats:

```json
{
  "result": "continue"
}
```

This means that the plugin does not want to do anything special and
`lightningd` should continue processing it normally, i.e., resolve the payment
if we're the recipient, or attempt to forward it otherwise. Notice that the
usual checks such as sufficient fees and CLTV deltas are still enforced.

It can also replace the `onion.payload` by specifying a `payload` in
the response.  Note that this is always a TLV-style payload, so unlike
`onion.payload` there is no length prefix (and it must be at least 4
hex digits long).  This will be re-parsed; it's useful for removing
onion fields which a plugin doesn't want lightningd to consider.


```json
{
  "result": "fail",
  "failure_message": "2002"
}
```

`fail` will tell `lightningd` to fail the HTLC with a given hex-encoded
`failure_message` (please refer to the [spec][bolt4-failure-messages] for
details: `incorrect_or_unknown_payment_details` is the most common).


```json
{
  "result": "fail",
  "failure_onion": "[serialized error packet]"
}
```

Instead of `failure_message` the response can contain a hex-encoded
`failure_onion` that will be used instead (please refer to the
[spec][bolt4-failure-onion] for details). This can be used, for example,
if you're writing a bridge between two Lightning Networks. Note that
`lightningd` will apply the obfuscation step to the value returned here
with its own shared secret (and key type `ammag`) before returning it to
the previous hop.


```json
{
  "result": "resolve",
  "payment_key": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

`resolve` instructs `lightningd` to claim the HTLC by providing the preimage
matching the `payment_hash` presented in the call. Notice that the plugin must
ensure that the `payment_key` really matches the `payment_hash` since
`lightningd` will not check and the wrong value could result in the channel
being closed.

Warning: `lightningd` will replay the HTLCs for which it doesn't have a final
verdict during startup. This means that, if the plugin response wasn't
processed before the HTLC was forwarded, failed, or resolved, then the plugin
may see the same HTLC again during startup. It is therefore paramount that the
plugin is idempotent if it talks to an external system.

The `htlc_accepted` hook is a chained hook, i.e., multiple plugins can
register it, and they will be called in the order they were registered in
until the first plugin return a result that is not `{"result": "continue"}`,
after which the event is considered to be handled. After the event has been
handled the remaining plugins will be skipped.


### `rpc_command`

The `rpc_command` hook allows a plugin to take over any RPC command. It sends
the received JSON-RPC request to the registered plugin,

```json
{
    "rpc_command": {
        "id": 3,
        "method": "method_name",
        "params": {
            "param_1": [],
            "param_2": {},
            "param_n": "",
        }
    }
}
```

which can in turn:

Let `lightningd` execute the command with

```json
{
    "result" : "continue"
}
```
Replace the request made to `lightningd`:

```json
{
    "replace": {
        "id": 3,
        "method": "method_name",
        "params": {
            "param_1": [],
            "param_2": {},
            "param_n": "",
        }
    }
}
```

Return a custom response to the request sender:

```json
{
    "return": {
        "result": {
        }
    }
}
```

Return a custom error to the request sender:

```json
{
    "return": {
        "error": {
        }
    }
}
```

Note: The `rpc_command` hook is chainable. If two or more plugins try to
replace/result/error the same `method`, only the first plugin in the chain
will be respected. Others will be ignored and a warning will be logged.

### `custommsg`

The `custommsg` plugin hook is the receiving counterpart to the
[`dev-sendcustommsg`][sendcustommsg] RPC method and allows plugins to handle
messages that are not handled internally. The goal of these two components is
to allow the implementation of custom protocols or prototypes on top of a
c-lightning node, without having to change the node's implementation itself.

The payload for a call follows this format:

```json
{
	"peer_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
	"payload": "1337ffffffff"
}
```

This payload would have been sent by the peer with the `node_id` matching
`peer_id`, and the message has type `0x1337` and contents `ffffffff`. Notice
that the messages are currently limited to odd-numbered types and must not
match a type that is handled internally by c-lightning. These limitations are
in place in order to avoid conflicts with the internal state tracking, and
avoiding disconnections or channel closures, since odd-numbered message can be
ignored by nodes (see ["it's ok to be odd" in the specification][oddok] for
details). The plugin must implement the parsing of the message, including the
type prefix, since c-lightning does not know how to parse the message.

Because this is a chained hook, the daemon expects the result to be
`{'result': 'continue'}`. It will fail if something else is returned.

### `onion_message` and `onion_message_blinded`

**(WARNING: experimental-offers only)**

These two hooks are almost identical, in that they are called when an
onion message is received.  The former is only used for unblinded
messages (where the source knows that it is sending to this node), and
the latter for blinded messages (where the source doesn't know that
this node is the destination).  The latter hook will have a
"blinding_in" field, the former never will.

These hooks are separate, because blinded messages must ensure the
sender used the correct "blinding_in", otherwise it should ignore the
message: this avoids the source trying to probe for responses without
using the designated delivery path.

The payload for a call follows this format:

```json
{
    "onion_message": {
        "blinding_in": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
		"reply_path": [ {"id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
                         "enctlv": "0a020d0d",
                         "blinding": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"} ],
        "invoice_request": "0a020d0d",
		"invoice": "0a020d0d",
		"invoice_error": "0a020d0d",
		"unknown_fields": [ {"number": 12345, "value": "0a020d0d"} ]
	}
}
```

All fields shown here are optional.

We suggest just returning `{'result': 'continue'}`; any other result
will cause the message not to be handed to any other hooks.

## Bitcoin backend

C-lightning communicates with the Bitcoin network through a plugin. It uses the
`bcli` plugin by default but you can use a custom one, multiple custom ones for
different operations, or write your own for your favourite Bitcoin data source!

Communication with the plugin is done through 5 JSONRPC commands, `lightningd`
can use from 1 to 5 plugin(s) registering these 5 commands for gathering Bitcoin
data. Each plugin must follow the below specification for `lightningd` to operate.


### `getchaininfo`

Called at startup, it's used to check the network `lightningd` is operating on and to
get the sync status of the backend.

The plugin must respond to `getchaininfo` with the following fields:
    - `chain` (string), the network name as introduced in bip70
    - `headercount` (number), the number of fetched block headers
    - `blockcount` (number), the number of fetched block body
    - `ibd` (bool), whether the backend is performing initial block download


### `estimatefees`

Polled by `lightningd` to get the current feerate, all values must be passed in sat/kVB.

If fee estimation fails, the plugin must set all the fields to `null`.

The plugin, if fee estimation succeeds, must respond with the following fields:
    - `opening` (number), used for funding and also misc transactions
    - `mutual_close` (number), used for the mutual close transaction
    - `unilateral_close` (number), used for unilateral close (/commitment) transactions
    - `delayed_to_us` (number), used for resolving our output from our unilateral close
    - `htlc_resolution` (number), used for resolving HTLCs after an unilateral close
    - `penalty` (number), used for resolving revoked transactions
    - `min_acceptable` (number), used as the minimum acceptable feerate
    - `max_acceptable` (number), used as the maximum acceptable feerate


### `getrawblockbyheight`

This call takes one parameter, `height`, which determines the block height of
the block to fetch.

The plugin must set all fields to `null` if no block was found at the specified `height`.

The plugin must respond to `getrawblockbyheight` with the following fields:
    - `blockhash` (string), the block hash as a hexadecimal string
    - `block` (string), the block content as a hexadecimal string


### `getutxout`

This call takes two parameter, the `txid` (string) and the `vout` (number)
identifying the UTXO we're interested in.

The plugin must set both fields to `null` if the specified TXO was spent.

The plugin must respond to `gettxout` with the following fields:
    - `amount` (number), the output value in **sats**
    - `script` (string), the output scriptPubKey


### `sendrawtransaction`

This call takes two parameters,
a string `tx` representing a hex-encoded Bitcoin transaction,
and a boolean `allowhighfees`, which if set means suppress
any high-fees check implemented in the backend, since the given
transaction may have fees that are very high.

The plugin must broadcast it and respond with the following fields:
    - `success` (boolean), which is `true` if the broadcast succeeded
    - `errmsg` (string), if success is `false`, the reason why it failed


[jsonrpc-spec]: https://www.jsonrpc.org/specification
[jsonrpc-notification-spec]: https://www.jsonrpc.org/specification#notification
[bolt4]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md
[bolt4-failure-messages]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#failure-messages
[bolt4-failure-onion]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#returning-errors
[bolt2-open-channel]: https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#the-open_channel-message
[sendcustommsg]: lightning-dev-sendcustommsg.7.html
[oddok]: https://github.com/lightningnetwork/lightning-rfc/blob/master/00-introduction.md#its-ok-to-be-odd
[spec]: [https://github.com/lightningnetwork/lightning-rfc]
[bolt9]: https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md
