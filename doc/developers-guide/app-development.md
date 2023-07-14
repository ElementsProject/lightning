---
title: "App Development"
slug: "app-development"
excerpt: "Build a lightning application using Core Lightning APIs."
hidden: false
createdAt: "2022-12-09T09:56:04.704Z"
updatedAt: "2023-02-21T13:48:15.261Z"
---
There are several ways to connect and interact with a Core Lightning node in order to build a lightning app or integrate lightning in your application.

- Using **[JSON-RPC commands](doc:json-rpc) **if you're building an application in the same system as the CLN node.
- Using **[gRPC APIs](doc:grpc)** if you're building an application in a remote client and want to connect to the CLN node over a secure network.
- Using **[Commando](doc:commando)** to connect to a CLN node over the lightning network and issue commands.
- Third-party libraries that offer **[REST](doc:third-party-libraries#rest)**, **[GraphQL](doc:third-party-libraries#graphql)** or **[JSON over HTTPS](doc:third-party-libraries#json-over-https)** frameworks to connect to a CLN node remotely.

[block:image]
{
  "images": [
    {
      "image": [
        "https://files.readme.io/b8d50a6-cln-api.png",
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