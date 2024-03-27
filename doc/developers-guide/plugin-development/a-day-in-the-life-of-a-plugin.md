---
title: "A day in the life of a plugin"
slug: "a-day-in-the-life-of-a-plugin"
hidden: false
createdAt: "2023-02-03T08:32:53.431Z"
updatedAt: "2023-07-12T13:48:23.030Z"
---
A plugin may be written in any language, and communicates with `lightningd` through the plugin's `stdin` and `stdout`. JSON-RPCv2 is used as protocol on top of the two streams, with the plugin acting as server and `lightningd` acting as client. The plugin file needs to be executable (e.g. use `chmod a+x plugin_name`).

> 🚧 
> 
> As noted, `lightningd` uses `stdin` as an intake mechanism.  This can cause unexpected behavior if one is not careful.  To wit, care should be taken to ensure that debug/logging statements must be routed to `stderr` or directly to a file. Activities that are benign in other contexts (`println!`, `dbg!`, etc) will cause the plugin to be killed with an error along the lines of:
> 
> `UNUSUAL plugin-cln-plugin-startup: Killing plugin: JSON-RPC message
> does not contain "jsonrpc" field`

During startup of `lightningd` you can use the `--plugin=` option to register one or more plugins that should be started. In case you wish to start several plugins you have to use the `--plugin=` argument once for each plugin (or `--plugin-dir` or place them in the default  
plugin dirs, usually `/usr/local/libexec/c-lightning/plugins` and `~/.lightning/plugins`). An example call might look like:

```
lightningd --plugin=/path/to/plugin1 --plugin=path/to/plugin2
```

`lightningd` will run your plugins from the `--lightning-dir`/networkname as working directory and env variables "LIGHTNINGD_PLUGIN" and "LIGHTNINGD_VERSION" set, then will write JSON-RPC requests to the plugin's `stdin` and will read replies from its `stdout`. To initialise the plugin two RPC methods are required:

- `getmanifest` asks the plugin for command line options and JSON-RPC commands that should be passed through.  This can be run before `lightningd` checks that it is the sole user of the `lightning-dir` directory (for `--help`) so your plugin should not touch files at this point.
- `init` is called after the command line options have been parsed and passes them through with the real values (if specified). This is also the signal that `lightningd`'s JSON-RPC over Unix Socket is now up and ready to receive incoming requests from the plugin.

Once those two methods were called `lightningd` will start passing through incoming JSON-RPC commands that were registered and the plugin may interact with `lightningd` using the JSON-RPC over Unix-Socket interface.

Above is generally valid for plugins that start when `lightningd` starts. For dynamic plugins that start via the [lightning-plugin](ref:lightning-plugin) JSON-RPC command there is some difference, mainly in options passthrough (see note in [Types of Options](doc:a-day-in-the-life-of-a-plugin#types-of-options)).

- `shutdown` (optional): if subscribed to "shutdown" notification, a plugin can exit cleanly when `lightningd` is shutting down or when stopped via `plugin stop`.

### The `getmanifest` method

The `getmanifest` method is required for all plugins and will be called on startup with optional parameters (in particular, it may have `allow-deprecated-apis: false`, but you should accept, and ignore, other parameters).  It MUST return a JSON object similar to this example:

```json
{
  "options": [
    {
      "name": "greeting",
      "type": "string",
      "default": "World",
      "description": "What name should I call you?",
      "deprecated": false,
      "dynamic": false
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
    "deprecated_oneshot",
    "connect",
    "disconnect"
  ],
  "hooks": [
    {
      "name": "openchannel",
      "before": [
        "another_plugin"
      ]
    },
    {
      "name": "htlc_accepted"
    }
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
  "custommessages": [
    11008,
    11010
  ],
  "nonnumericids": true,
  "cancheck": true,
  "dynamic": true
}
```

During startup the `options` will be added to the list of command line options that `lightningd` accepts. If any `options` "name" is already taken startup will abort. The above will add a `--greeting` option with a default value of `World` and the specified description. _Notice that currently string, integers, bool, and flag options are supported._ If an option specifies `dynamic`: `true`, then it should allow a `setconfig` call for that option after initialization.

The `rpcmethods` are methods that will be exposed via `lightningd`'s JSON-RPC over Unix-Socket interface, just like the builtin commands. Any parameters given to the JSON-RPC calls will be passed through verbatim. Notice that the `name`, `description` and `usage` fields are mandatory, while the `long_description` can be omitted (it'll be set to `description` if it was not provided). `usage` should surround optional parameter names in `[]`.

`options` and `rpcmethods` can mark themselves `deprecated: true` if you plan on removing them: this will disable them if the user sets `allow-deprecated-apis` to false, or in `--developer` mode.  You can also specify `deprecated` as an array of one or two version numbers, indicating when deprecation starts, and the final version it will be permitted, e.g. `"deprecated": ["v24.02", "v24.02"]`.  If only one version number is given, then the final version will be 6 months after the start version.

The `subscriptions` array indicates what [Event Notifications](doc:event-notifications) your plugin wants to receive.  You should subscribe to `deprecated_oneshot` if you have any deprecated commands or output, so users can use the `deprecations` API to control it on a per-connection basis.  You can specify `*` here to subscribe to all other subscriptions (since *v23.08*).

The `nonnumericids` indicates that the plugin can handle string JSON request `id` fields: prior to v22.11 lightningd used numbers for these, and the change to strings broke some plugins.  If not set, then strings will be used once this feature is removed after v23.05. See the [lightningd-rpc](ref:lightningd-rpc) documentation for how to handle JSON `id` fields!

The `dynamic` indicates if the plugin can be managed after `lightningd` has been started using the [lightning-plugin](ref:lightning-plugin) JSON-RPC command. Critical plugins that should not be stopped should set it to false. Plugin `options` can be passed to dynamic plugins as argument to the `plugin` command .

If you can handle the `check` command on your commands, you should set `cancheck` to `true` and expect `lightningd` to pass through any user-requested `check` commands to you directly (without this, `check` currently always passes, which is not very useful!).
  
If a `disable` member exists, the plugin will be disabled and the contents of this member is the reason why.  This allows plugins to disable themselves if they are not supported in this configuration.

The `featurebits` object allows the plugin to register featurebits that should be announced in a number of places in [the protocol](https://github.com/lightning/bolts/blob/master/09-features). They can be used to signal support for custom protocol extensions to direct peers, remote nodes and in invoices. Custom protocol extensions can be implemented for example using the `sendcustommsg` method and the `custommsg` hook, or the `sendonion` method and the `htlc_accepted` hook. The keys in the `featurebits` object are `node` for features that should be announced via the `node_announcement` to all nodes in the network, `init` for features that should be announced to direct peers during the connection setup, `channel` for features which should apply to `channel_announcement`, and `invoice` for features that should be announced to a potential sender of a payment in the invoice. The low range of featurebits is reserved for standardize features, so please pick random, high position bits for experiments. If you'd like to standardize your extension please reach out to the [specification repository][spec] to get a featurebit assigned.

The `notifications` array allows plugins to announce which custom notifications they intend to send to `lightningd`. These custom notifications can then be subscribed to by other plugins, allowing them to communicate with each other via the existing publish-subscribe mechanism and react to events that happen in other plugins, or collect information based on the notification topics.

The `custommessages` array allows the plugin to tell `lightningd` to explicitly allow these (unknown) custom messages: we normally disconnect with an error if we receive these.  This only makes sense if you also subscribe to the `custommsg` hook.

Plugins are free to register any `name` for their `rpcmethod` as long as the name was not previously registered. This includes both built-in methods, such as `help` and `getinfo`, as well as methods registered by other plugins. If there is a conflict then `lightningd` will report an error and kill the plugin, this aborts startup if the plugin is _important_.

#### Types of Options

There are currently four supported option 'types':

- string: a string
- bool: a boolean
- int: parsed as a signed integer (64-bit)
- flag: no-arg flag option. Presented as `true` if config specifies it.

In addition, string and int types can specify `"multi": true` to indicate they can be specified multiple times.  These will always be represented in `init` as a (possibly empty) JSON array. "multi" flag types do not make  
sense.

Nota bene: if a `flag` type option is not set, it will not appear in the options set that is passed to the plugin.

Here's an example option set, as sent in response to `getmanifest`

```json
{
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
  ]
}
```

#### Custom notifications

The plugins may emit custom notifications for topics they have announced during startup. The list of notification topics declared during startup must include all topics that may be emitted, in order to verify that all topics plugins subscribe to are also emitted by some other plugin, and warn if a plugin subscribes to a non-existent topic. In case a plugin emits notifications it has not announced the notification will be ignored and not forwarded to subscribers.

When forwarding a custom notification `lightningd` will wrap the payload of the notification in an object that contains metadata about the notification. The following is an example of this transformation. The first listing is the original notification emitted by the `sender` plugin, while the second is the the notification as received by the `receiver` plugin (both listings show the full [JSON-RPC](https://www.jsonrpc.org/specification) notification to illustrate the wrapping).

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

The notification topic (`method` in the JSON-RPC message) must not match one of the internal events in order to prevent breaking subscribers that expect the existing notification format. Multiple plugins are allowed to emit notifications for the same topics, allowing things like metric aggregators where the aggregator subscribes to a common topic and other plugins publish metrics as notifications.

### The `init` method

The `init` method is required so that `lightningd` can pass back the filled command line options and notify the plugin that `lightningd` is now ready to receive JSON-RPC commands. The `params` of the call are a simple JSON object containing the options:

```json
{
  "options": {
    "greeting": "World",
    "number": [
      0
    ]
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
    "always_use_proxy": false
  }
}
```

The plugin must respond to `init` calls.  The response should be a valid JSON-RPC response to the `init`, but this is not currently enforced.  If the response is an object containing `result` which contains `disable` then the plugin will be disabled and the contents  
of this member is the reason why.

The `startup` field allows a plugin to detect if it was started at `lightningd` startup (true), or at runtime (false).

### Timeouts

During startup ("startup" is true), the plugin has 60 seconds to return `getmanifest` and another 60 seconds to return `init`, or gets killed.  
When started dynamically via the [lightning-plugin](ref:lightning-plugin) JSON-RPC command, both `getmanifest` and `init` should be completed within 60 seconds.
