---
title: Hooks
slug: hooks
privacy:
  view: public
---
Hooks allow a plugin to define custom behavior for `lightningd` without having to modify the Core Lightning source code itself. A plugin declares that it'd like to be consulted on what to do next for certain events in the daemon. A hook can then decide how `lightningd` should react to the given event.

When hooks are registered, they can optionally specify "before" and "after" arrays of plugin names, which control what order they will be called in. If a plugin name is unknown, it is ignored, otherwise if the hook calls cannot be ordered to satisfy the specifications of all plugin hooks, the plugin registration will fail.

The call semantics of the hooks, i.e., when and how hooks are called, depend on the hook type. Most hooks are currently set to `single`-mode. In this mode only a single plugin can register the hook, and that plugin will get called for each event of that type. If a second plugin attempts to register the hook it gets killed and a corresponding log entry will be added to the logs.

In `chain`-mode multiple plugins can register for the hook type and they are called in any order they are loaded (i.e. cmdline order first, configuration order file second: though note that the order of plugin directories is implementation-dependent), overridden only by `before` and `after` requirements the plugin's hook registrations specify. Each plugin can then handle the event or defer by returning a `continue` result like the following:
```json
{
  "result": "continue"
}
```

The remainder of the response is ignored and if there are any more plugins that have registered the hook the next one gets called. If there are no more plugins then the internal handling is resumed as if no hook had been called. Any other result returned by a plugin is considered an exit from the chain. Upon exit no more plugin hooks are called for the current event, and the result is executed. Unless otherwise stated all hooks are `single`-mode.

Hooks and notifications are very similar, however there are a few key differences:

- Notifications are asynchronous, i.e., `lightningd` will send the notifications but not wait for the plugin to process them. Hooks on the other hand are synchronous, `lightningd` cannot finish processing the event until the plugin has returned.
- Any number of plugins can subscribe to a notification topic and get notified in parallel, however only one plugin may register for `single`-mode hook types, and in all cases only one plugin may return a non-`continue` response. This avoids having multiple contradictory responses.

Hooks are considered to be an advanced feature due to the fact that `lightningd` relies on the plugin to tell it what to do next. Use them carefully, and make sure your plugins always return a valid response to any hook invocation.

As a convention, for all hooks, returning the object `{ "result" : "continue" }` results in `lightningd` behaving exactly as if no plugin is registered on the hook.

Lookup the **[Hook APIs](ref:hook-commitment_revocation)** for details on each hook's payload and how to respond to them.
