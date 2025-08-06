---
title: "Commando Plugin"
slug: "commando-plugin"
hidden: false
createdAt: "2023-02-08T09:54:01.784Z"
updatedAt: "2023-09-05T13:55:16.224Z"
---
> 📘 
> 
> Used for applications that want to connect to a CLN node over the lightning network in a secure manner.

Commando is a direct-to-node plugin that ships natively with Core Lightning. It lets you set _runes_ to create fine-grained access controls to a CLN node's RPC and provides access to those same RPCs via Lightning-native network connections. 

The commando plugin uses RPC method `commando` which allows you to send a directly connected peer an RPC request. In turn, it will run and send the result to you. This uses the secure connections that Lightning nodes establish with each other on connect. As arbitrary RPC executions by any connected node can be dangerous, generally, the peer will only allow you to execute the command if you've also provided a `rune`.

For more details on using runes, read through the docs for [commando](ref:commando).

Check out [this](https://www.youtube.com/watch?v=LZLRCPNn7vA) video of William Casarin (@jb55) walking through how to create runes and connect to a Lightning node via [lnsocket](https://github.com/jb55/lnsocket).


> 📘 Pro-tip
>
> - **[lnmessage](https://github.com/aaronbarnardsound/lnmessage)** allows you to talk to Core Lightning nodes from the browser via a Websocket connection and controls it using commando.
>
> - **[lnsocket](https://github.com/jb55/lnsocket)** allows you to build a web or mobile app that talks directly to a CLN node over commando with runes. Check out [LNLink](https://lnlink.app/) -  a mobile app that allows you to control a Core Lightning node over the lightning network itself!
