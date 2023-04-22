---
title: "Plugin Development"
slug: "plugin-development"
excerpt: "Customise your Core Lightning node by leveraging its powerful modular architecture via plugins."
hidden: false
createdAt: "2022-12-09T09:56:22.085Z"
updatedAt: "2023-02-06T03:21:36.614Z"
---
Plugins are a simple yet powerful way to extend the functionality provided by Core Lightning. They are subprocesses that are started by the main `lightningd` daemon and can interact with `lightningd` in a variety of ways:

- **[Command line option passthrough](doc:a-day-in-the-life-of-a-plugin)** allows plugins to register their own command line options that are exposed through `lightningd` so that only the main process needs to be configured. Option values are not remembered when a plugin is stopped or killed, but can be passed as parameters to [`plugin start`][lightning-plugin].
- **[JSON-RPC command passthrough](doc:json-rpc-passthrough)** adds a way for plugins to add their own commands to the JSON-RPC interface.
- **[Event stream subscriptions](doc:event-notifications)** provide plugins with a push-based notification mechanism about events from the `lightningd`.
- **[Hooks](doc:hooks)** are a primitive that allows plugins to be notified about internal events in `lightningd` and alter its behavior or inject custom behaviors.