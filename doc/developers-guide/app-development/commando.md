---
title: "Commando"
slug: "commando"
hidden: false
createdAt: "2023-02-08T09:54:01.784Z"
updatedAt: "2023-02-21T13:55:16.224Z"
---
> 📘 
> 
> Used for applications that want to connect to a CLN node over the lightning network in a secure manner.

Commando is a direct-to-node plugin that ships natively with Core Lightning. It lets you set _runes_ to create fine-grained access controls to a CLN node's RPC , and provides access to those same RPCs via Lightning-native network connections. 

The commando plugin adds two new RPC methods: `commando` and `commando-rune`.

- `commando` allows you to send a directly connected peer an RPC request, who, in turn, will run and send the result to you. This uses the secure connections that Lightning nodes establish with each other on connect. As arbitrary RPC executions by any connected node can be dangerous, generally, the peer will only allow you to execute the command if you've also provided a `rune`.
- `commando-rune` is the RPC command that allows you to construct a base64 encoded permissions string, which can be handed to peers to allow them to use commando to query or ask your node for things remotely. runes have restrictions added to them, meaning no one can remove a restriction from a rune you've generated and handed them. These restrictions allow you to carefully craft the RPC commands a caller is allowed to access, the number of times that they can do so, the length of time the rune is valid for, and more.

For more details on using runes, read through the docs for [commando](ref:lightning-commando) and [commando-rune](ref:lightning-commando-rune).

Check out [this](https://www.youtube.com/watch?v=LZLRCPNn7vA) video of William Casarin (@jb55) walking through how to create runes and connect to a Lightning node via [lnsocket](https://github.com/jb55/lnsocket).



> 📘 Pro-tip
> 
> - **[lnsocket](https://github.com/jb55/lnsocket)** allows you to build a web or mobile app that talks directly to a CLN node over commando with runes. Check out [LNLink](https://lnlink.app/) -  a mobile app that allows you to control a Core Lightning node over the lightning network itself!
> - **[lnmessage](https://github.com/aaronbarnardsound/lnmessage)** allows you to talk to Core Lightning nodes from the browser via a Websocket connection and control it using commando.