---
title: "Setting up a dev environment"
slug: "developers-guide"
excerpt: "Get up and running in your local environment with essential tools and libraries in your preferred programming language."
hidden: false
createdAt: "2022-11-18T14:28:23.407Z"
updatedAt: "2023-02-08T11:42:44.759Z"
---
## Using `startup_regtest.sh`

The Core Lightning project provides a script `startup_regtest.sh` to simulate the Lightning Network in your local dev environment. The script starts up some local nodes with bitcoind, all running on regtest and makes it easier to test things out, by hand.

Navigate to `contrib` in your Core Lightning directory:

```shell
cd contrib
```

Load the script, using `source` so it can set aliases:

```shell
source startup_regtest.sh
```

Start up the nodeset:

```shell
start_ln 3
```

Connect the nodes. The `connect a b` command connects node a to b:

```shell
connect 1 2
```

When you're finished, stop:

```shell
stop_ln
```

Clean up the lightning directories:

```shell
 destroy_ln
```



## Using Polar

[Polar](https://lightningpolar.com/) offers a one-click setup of Lightning Network for local app development & testing.
