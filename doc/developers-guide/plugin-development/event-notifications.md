---
title: Event notifications
slug: event-notifications
privacy:
  view: public
---
Event notifications allow a plugin to subscribe to events in `lightningd`. `lightningd` will then send a push notification if an event matching the subscription occurred. A notification is defined in the JSON-RPC [specification][jsonrpc-spec] as an RPC call that does not include an `id` parameter:

> A Notification is a Request object without an "id" member. A Request object that is a Notification signifies the Client's lack of interest in the corresponding Response object, and as such no Response object needs to be returned to the client. The Server MUST NOT reply to a Notification, including those that are within a batch request.
>
> Notifications are not confirmable by definition, since they do not have a Response object to be returned. As such, the Client would not be aware of any errors (like e.g. "Invalid params","Internal error").

Plugins subscribe by returning an array of subscriptions as part of the `getmanifest` response. The result for the `getmanifest` call above for example subscribes to the two topics `connect` and `disconnect`.

> 📘 
> 
> This is a way of specifying that you want to subscribe to all possible event notifications. It is not recommended, but is useful for plugins which want to provide generic infrastructure for others (in future, we may add the ability to dynamically subscribe/unsubscribe).

Lookup the **[Notification APIs](ref:notification-balance_snapshot)** for details on each notification and their payload.
