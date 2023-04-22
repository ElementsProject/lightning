---
title: "JSON-RPC passthrough"
slug: "json-rpc-passthrough"
hidden: false
createdAt: "2023-02-03T08:53:50.840Z"
updatedAt: "2023-02-03T08:53:50.840Z"
---
Plugins may register their own JSON-RPC methods that are exposed through the JSON-RPC provided by `lightningd`. This provides users with a single interface to interact with, while allowing the addition of custom methods without having to modify the daemon itself.

JSON-RPC methods are registered as part of the `getmanifest` result. Each registered method must provide a `name` and a `description`. An optional `long_description` may also be  
provided. This information is then added to the internal dispatch table, and used to return the help text when using `lightning-cli
help`, and the methods can be called using the `name`.

For example, `getmanifest` result will register two methods, called `hello` and `gettime`:

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



The RPC call will be passed through unmodified, with the exception of the JSON-RPC call `id`, which is internally remapped to a unique integer instead, in order to avoid collisions. When passing the result back the `id` field is restored to its original value.

Note that if your `result` for an RPC call includes `"format-hint":
"simple"`, then `lightning-cli` will default to printing your output in "human-readable" flat form.