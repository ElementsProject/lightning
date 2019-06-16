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
once for each plugin. An example call might look like:

```
lightningd --plugin=/path/to/plugin1 --plugin=path/to/plugin2
```

`lightningd` will write JSON-RPC requests to the plugin's `stdin` and
will read replies from its `stdout`. To initialize the plugin two RPC
methods are required:

 - `getmanifest` asks the plugin for command line options and JSON-RPC
   commands that should be passed through
 - `init` is called after the command line options have been
   parsed and passes them through with the real values (if specified). This is also
   the signal that `lightningd`'s JSON-RPC over Unix Socket is now up
   and ready to receive incoming requests from the plugin.

Once those two methods were called `lightningd` will start passing
through incoming JSON-RPC commands that were registered and the plugin
may interact with `lightningd` using the JSON-RPC over Unix-Socket
interface.

### The `getmanifest` method

The `getmanifest` method is required for all plugins and will be called on
startup without any params. It MUST return a JSON object similar to
this example:

```json
{
	"options": [
		{
			"name": "greeting",
			"type": "string",
			"default": "World",
			"description": "What name should I call you?"
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
			"long_description": "Returns the current time in the timezone that is given as the only parameter.\nThis description may be quite long and is allowed to span multiple lines."
		}
	],
	"subscriptions": [
		"connect",
		"disconnect"
	]
}
```

The `options` will be added to the list of command line options that
`lightningd` accepts. The above will add a `--greeting` option with a
default value of `World` and the specified description. *Notice that
currently string, (unsigned) integers, and bool options are supported.*

The `rpcmethods` are methods that will be exposed via `lightningd`'s
JSON-RPC over Unix-Socket interface, just like the builtin
commands. Any parameters given to the JSON-RPC calls will be passed
through verbatim. Notice that the `name`, `description` and `usage` fields
are mandatory, while the `long_description` can be omitted (it'll be
set to `description` if it was not provided). `usage` should surround optional
parameter names in `[]`.

Plugins are free to register any `name` for their `rpcmethod` as long
as the name was not previously registered. This includes both built-in
methods, such as `help` and `getinfo`, as well as methods registered
by other plugins. If there is a conflict then `lightningd` will report
an error and exit.

### The `init` method

The `init` method is required so that `lightningd` can pass back the
filled command line options and notify the plugin that `lightningd` is
now ready to receive JSON-RPC commands. The `params` of the call are a
simple JSON object containing the options:

```json
{
	"options": {
		"greeting": "World"
	},
	"configuration": {
		 "lightning-dir": "/home/user/.lightning",
		 "rpc-file": "lightning-rpc"
	}
}
```

The plugin must respond to `init` calls, however the response can be
arbitrary and will currently be discarded by `lightningd`. JSON-RPC
commands were chosen over notifications in order not to force plugins
to implement notifications which are not that well supported.

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

### Notification Types

#### `connect`

A notification for topic `connect` is sent every time a new connection
to a peer is established.

```json
{
	"id": "02f6725f9c1c40333b67faea92fd211c183050f28df32cac3f9d69685fe9665432",
	"address": "1.2.3.4"
}
```

#### `disconnect`

A notification for topic `disconnect` is sent every time a connection
to a peer was lost.

```json
{
	"id": "02f6725f9c1c40333b67faea92fd211c183050f28df32cac3f9d69685fe9665432"
}
```

#### `warning`

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

## Hooks

Hooks allow a plugin to define custom behavior for `lightningd`
without having to modify the c-lightning source code itself. A plugin
declares that it'd like to consulted on what to do next for certain
events in the daemon. A hook can then decide how `lightningd` should
react to the given event.

Hooks and notifications sounds very similar, however there are a few
key differences:

 - Notifications are asynchronous, i.e., `lightningd` will send the
   notifications but not wait for the plugin to process them. Hooks on
   the other hand are synchronous, `lightningd` cannot finish
   processing the event until the plugin has returned.
 - Any number of plugins can subscribe to a notification topic,
   however only one plugin may register for any hook topic at any
   point in time (we cannot disambiguate between multiple plugins
   returning contradictory results from a hook callback).

Hooks are considered to be an advanced feature due to the fact that
`lightningd` relies on the plugin to tell it what to do next. Use them
carefully, and make sure your plugins always return a valid response
to any hook invocation.

### Hook Types

#### `peer_connected`

This hook is called whenever a peer has connected and successfully completed
the cryptographic handshake. The parameters have the following structure if there is a channel with the peer:

```json
{
  "peer": {
	"id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
	"addr": "34.239.230.56:9735",
	"globalfeatures": "",
	"localfeatures": ""
  }
}
```

The hook is sparse on purpose, since the plugin can use the JSON-RPC
`listpeers` command to get additional details should they be required. The
`addr` field shows the address that we are connected to ourselves, not the
gossiped list of known addresses. In particular this means that the port for
incoming connections is an ephemeral port, that may not be available for
reconnections.

The returned result must contain a `result` member which is either
the string `disconnect` or `continue`.  If `disconnect` and
there's a member `error_message`, that member is sent to the peer
before disconnection.


#### `db_write`

This hook is called whenever a change is about to be committed to the database.
It is currently extremely restricted:

1. a plugin registering for this hook should not perform anything that may cause
   a db operation in response (pretty much, anything but logging).
2. a plugin registering for this hook should not register for other hooks or
   commands, as these may become intermingled and break rule #1.
3. the hook will be called before your plugin is initialized!

```json
{
  "writes": [ "PRAGMA foreign_keys = ON" ]
}
```

Any response but "true" will cause lightningd to error without
committing to the database!

#### `invoice_payment`

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

The hook is sparse on purpose, since the plugin can use the JSON-RPC
`listinvoices` command to get additional details about this invoice.
It can return a non-zero `failure_code` field as defined for final
nodes in [BOLT 4][bolt4-failure-codes], or otherwise an empty object
to accept the payment.


#### `openchannel`

This hook is called whenever a remote peer tries to fund a channel to us,
and it has passed basic sanity checks:

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

#### `htlc_accepted`

The `htlc_accepted` hook is called whenever an incoming HTLC is accepted, and
its result determines how `lightningd` should treat that HTLC.

The payload of the hook call has the following format:

```json
{
  "onion": {
    "payload": "",
    "per_hop_v0": {
      "realm": "00",
      "short_channel_id": "1x2x3",
      "forward_amount": "42msat",
      "outgoing_cltv_value": 500014
    }
  },
  "next_onion": "[1365bytes of serialized onion]",
  "shared_secret": "0000000000000000000000000000000000000000000000000000000000000000",
  "htlc": {
    "amount": "43msat",
    "cltv_expiry": 500028,
    "cltv_expiry_relative": 10,
    "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

The `per_hop_v0` will only be present if the per hop payload has format `0x00`
as defined by the specification. If not present an object representing the
type-length-vale (TLV) payload will be added (pending specification). For detailed information about each field please refer to [BOLT 04 of the specification][bolt4], the following is just a brief summary:

 - `onion.payload` contains the unparsed payload that was sent to us from the
   sender of the payment.
 - `onion.per_hop_v0`:
   - `realm` will always be `00` since that value determines that we are using
     the `per_hop_v0` format.
   - `short_channel_id` determines the channel that the sender is hinting
     should be used next (set to `0x0x0` if we are the recipient of the
     payment).
   - `forward_amount` is the amount we should be forwarding to the next hop,
     and should match the incoming funds in case we are the recipient.
   - `outgoing_cltv_value` determines what the CLTV value for the HTLC that we
     forward to the next hop should be.
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

```json
{
  "result": "fail",
  "failure_code": 4301
}
```

`fail` will tell `lightningd` to fail the HTLC with a given numeric
`failure_code` (please refer to the [spec][bolt4-failure-codes] for details).

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

[jsonrpc-spec]: https://www.jsonrpc.org/specification
[jsonrpc-notification-spec]: https://www.jsonrpc.org/specification#notification
[bolt4]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md
[bolt4-failure-codes]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#failure-messages
[bolt2-open-channel]: https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#the-open_channel-message
