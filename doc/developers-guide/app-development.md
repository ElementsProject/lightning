---
title: "App Development"
slug: "app-development"
excerpt: "Build a lightning application using Core Lightning APIs."
hidden: false
---
There are several ways to connect and interact with a Core Lightning node in order to build a lightning app or integrate lightning in your application.

- Using **[JSON-RPC commands](doc:json-rpc)** if you're building an application in the same system as the CLN node.
- Using **[REST APIs](doc:rest)** if you're building an application in a remote client and want to connect to the CLN node over a secure network using REST interface.
- Using **[gRPC APIs](doc:grpc)** if you're building an application in a remote client and want to connect to the CLN node over a secure network using gRPC interface.
- Using **[Commando](doc:commando)** to connect to a CLN node over the lightning network and issue commands.
- Using **[WSS Proxy](doc:wss-proxy)** to connect to a CLN node over web secure socket proxy.
- Third-party libraries that offer **[JSON over HTTPS](doc:third-party-libraries#json-over-https)** or **[GraphQL](doc:third-party-libraries#graphql)** (deprecated) frameworks to connect to a CLN node remotely.

[block:image]
{
  "images": [
    {
      "image": [
        "https://files.readme.io/a7cf433-CLN-App-Development.png",
        null,
        "A visual chart of all interface and transport protocols to interact with a CLN node."
      ],
      "align": "center",
      "border": true,
      "caption": "A visual chart of available API interfaces and transport protocols for interacting with a CLN node"
    }
  ]
}
[/block]
