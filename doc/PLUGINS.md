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
   
*Note: Hooks are not yet implemented, and the API is under active development.*

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
   parsed and passes them through with the real values. This is also
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
currently only string options are supported.*

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

[jsonrpc-spec]: https://www.jsonrpc.org/specification
[jsonrpc-notification-spec]: https://www.jsonrpc.org/specification#notification
