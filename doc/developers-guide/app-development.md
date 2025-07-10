---
title: "App Development"
slug: "app-development"
excerpt: "Build a lightning application using Core Lightning APIs."
hidden: false
---

## Interacting with CLN Node

There are several ways to connect and interact with a Core Lightning node in order to build a lightning app or integrate lightning in your application.

- Using **[JSON-RPC commands](doc:json-rpc)** if you're building an application in the same system as the CLN node.
- Using **[REST APIs](doc:rest)** if you're building an application in a remote client and want to connect to the CLN node over a secure network using REST interface.
- Using **[gRPC APIs](doc:grpc)** if you're building an application in a remote client and want to connect to the CLN node over a secure network using gRPC interface.
- Using **[Commando Plugin](doc:commando-plugin)** to connect to a CLN node over the lightning network and issue commands.
- Using **[WSS Proxy](doc:wss-proxy)** to connect to a CLN node over web secure socket proxy.
- Third-party libraries that offer **[JSON over HTTPS](doc:third-party-libraries#json-over-https)** or **[GraphQL](doc:third-party-libraries#graphql)** (deprecated) frameworks to connect to a CLN node remotely.

## CLN connection URIs

This section outlines the standard URI formats for connecting to Core Lightning (CLN) nodes via different protocols.

### Commando WebSocket Connection
```
commando+<protocol>://<cln-host>:<ws-port>?pubkey=<pubkey>&rune=<rune>&invoiceRune=<invoice-rune>&certs=<combined-base64-encoded-clientkey-clientcert-cacert>
```

#### Parameters:
- protocol: ws or wss (WebSocket or secure WebSocket)
- cln-host: Hostname or IP address of the CLN node
- ws-port: WebSocket port
- pubkey: Node's public key (hex encoded)
- rune: Authentication rune for general commands
- invoiceRune: Specific rune for invoice creation (optional)
- certs: Base64-encoded concatenation of client key, client cert, and CA cert

#### Example:

```
commando+wss://cln.local:5001?pubkey=023456789abcdef&rune=8hJ6ZKFvRune&invoiceRune=5kJ3ZKFvInvRune&certs=LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0t
```

### REST API Connection
```
clnrest+<protocol>://<rest-host>:<rest-port>?rune=<rune>&certs=<combined-base64-encoded-clientkey-clientcert-cacert>
```

#### Parameters:
- protocol: http or https
- rest-host: Hostname or IP address of the REST interface
- rest-port: REST API port (typically 3010)
- rune: Authentication rune for REST API access
- certs: Base64-encoded concatenation of client key, client cert, and CA cert

#### Example:

```
clnrest+https://cln.local:3010?rune=8hJ6ZKFvRune&certs=LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0t
```

## gRPC Connection

```
clngrpc://<grpc-host>:<grpc-port>?pubkey=<pubkey>&protoPath=<path-to-proto>&certs=<combined-base64-encoded-clientkey-clientcert-cacert>
```

#### Parameters:
- grpc-host: Hostname or IP address of the gRPC interface
- grpc-port: gRPC port (typically 9736)
- pubkey: Node's public key (hex encoded)
- protoPath: Path to protocol buffer definition file (typically https://github.com/ElementsProject/lightning/tree/master/cln-grpc/proto)
- certs: Base64-encoded concatenation of client key, client cert, and CA cert

#### Example:

```
clngrpc://cln.grpc:9736?pubkey=023456789abcdef&protoPath=/path/to/cln.proto&certs=LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0t
```

## Image of available API interfaces and transport protocols

[block:image]
{
  "images": [
    {
      "image": [
        "https://files.readme.io/3eeb3ddc8687fa45432c215777e478c40998bf94c42aeb1591c8096aac102e40-CLN-App-Development.png",
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
