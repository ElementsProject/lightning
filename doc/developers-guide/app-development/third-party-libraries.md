---
title: "Third-party libraries"
slug: "third-party-libraries"
hidden: false
createdAt: "2023-02-08T09:54:01.784Z"
updatedAt: "2023-09-05T13:55:16.224Z"
---

## GraphQL

[c-lightning-graphql](https://github.com/nettijoe96/c-lightning-graphql) exposes the Core Lightning API over GraphQL. 

> 🚧 
> 
> Note: It has not been maintained actively and should be used with caution.

## JSON over HTTPS

[Sparko](https://github.com/fiatjaf/sparko) offers a full-blown JSON-RPC over HTTP bridge to a CLN node with fine-grained permissions, SSE and spark-wallet support that can be used to develop apps.

## REST

> 📘 Pro-tip
> 
> Official support for REST APIs in Core Lightning has been released in v23.08!
>
> C-lightning-REST is scheduled to sunset soon!

[C-lightning-REST](https://github.com/Ride-The-Lightning/c-lightning-REST) is a _third party_ REST API interface for Core Lightning written in Node.js.

For new application development, utilize Core Lightning's first class REST plugin **[clnrest](doc:rest)**.
