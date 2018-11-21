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
   
*Notice: at the time of writing only command line option passthrough
is implemented, the other features are under active development.*

A plugin may be written in any language, and communicates with
`lightningd` through the plugin's `stdin` and `stdout`. JSON-RPCv2 is
used as protocol on top of the two streams, with the plugin acting as
server and `lightningd` acting as client.

## A day in the life of a plugin

During startup of `lightningd` you can use the `--plugin=` option to
register one or more plugins that should be started. `lightningd` will
write JSON-RPC requests to the plugin's `stdin` and will read replies
from its `stdout`. To initialize the plugin two RPC methods are
required:

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
			"description": "Returns a personalized greeting for {greeting} (set via options)."
		},
		{
			"name": "gettime",
			"description": "Returns the current time in {timezone}",
			"long_description": "Returns the current time in the timezone that is given as the only parameter.\nThis description may be quite long and is allowed to span multiple lines."
		}
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
through verbatim.

### The `init` method

The `init` method is required so that `lightningd` can pass back the
filled command line options and notify the plugin that `lightningd` is
now ready to receive JSON-RPC commands. The `params` of the call are a
simple JSON object containing the options:

```json
{
	"objects": {
		"greeting": "World"
	}
}
```

The plugin must respond to `init` calls, however the response can be
arbitrary and will currently be discarded by `lightningd`. JSON-RPC
commands were chosen over notifications in order not to force plugins
to implement notifications which are not that well supported.

## Event stream subscriptions

*TBD*

## Hooks

*TBD*
