# HOWTO USE TOR WITH C-LIGHTNING

to use tor you have to have tor installed an running.

i.e.
```
sudo apt install tor
```
then `/etc/init.d/tor start` or `sudo systemctl start tor` Depending 
on your system configuration.

If new to tor you might not change the default setting.

To keep The safe default with minimal harassment (See [Tor FAQ])
just check that this line is present in the file:

`ExitPolicy reject *:* # no exits allowed`

this does not affect c-lightning connect, listen, etc..
It will only prevent that you become a full exitpoint.
Only enable this if you are sure about the implications.

If we don't want to create .onion addresses this should be enough.

There are several way by which a c-lightning node can accept or make connections over Tor.

The node can be reached over Tor by connecting to its .onion address.

To provide the node with a .onion address is possible to:

* create a **non-persistent** address with an auto service or

* create a **persistent** address with an hidden service.

#### Creation of an auto service for non-persistent .onion addresses

To provide the node a non-persistent .onion address 
is necessary to access the Tor auto service. These types of addresses change 
each time the Tor service is restarted.

*NOTE:If the node is required to be reachable only by **persistent** .onion addresses, this 
part can be skipped and it is necessary to set up an hidden service with the steps 
outlined in the next section.*

To create and use the auto service follow this steps:

Edit the Tor config file `/etc/tor/torrc`

You can configure the service authenticated by cookie or by password:

##### Service authenticated by cookie 
We add the following lines in the `/etc/tor/torrc` file:

````
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
````

##### Service authenticated by password 

In alternative to the CookieFile authentication. you can set the authentication 
to the service with a password by following theses steps:

1. Create an hash of your password with 
```
tor --hash-password yourpassword
```
This returns a line like

`16:533E3963988E038560A8C4EE6BBEE8DB106B38F9C8A7F81FE38D2A3B1F`

2. put these lines in the `/etc/tor/torrc` file:
```
ControlPort 9051
HashedControlPassword 16:533E3963988E038560A8C4EE6BBEE8DB106B38F9C8A7F81FE38D2A3B1F
````
Save the file.

To activate these changes:

`/etc/init.d/tor restart`

The auto service will be used by adding `--addr=autotor:127.0.0.1:9051` if we 
want the address to be public or `--bind-addr=autotor:127.0.0.1:9051` if we 
don't want to publish it.

In the case the auto service is authenticated through the password, it will 
be necessary to add the option `--tor-service-password=yourpassword` (not the hash).

The created non-persistent .onion address wil be shown by the `lightning-cli getinfo`command. 
The others nodes will be able to `connect` to this .onion address through the 
9735 port.

#### Creation of an hidden service for a persistent .onion address

To have a persistent .onion address other nodes can connect to, it 
is necessary to set up a [Tor Hidden Service].

*NOTE: In the case only non-persistent addresses are required,  
you don't have to create the hidden service and you can skip this part.*

To do that we will add these lines in the `/etc/tor/torrc`file:

````
HiddenServiceDir /var/lib/tor/lightningd-service_v2/
HiddenServicePort 1234 127.0.0.1:9735
````

If we want to create a version 3 address, we will add also `HiddenServiceVersion 3` so
the whole section will be:

````
HiddenServiceDir /var/lib/tor/lightningd-service_v3/
HiddenServiceVersion 3
HiddenServicePort 1234 127.0.0.1:9735
````

The hidden lightning service  will be reachable at port 1234 (global port)
of the .onion address, which will be created at the restart of the 
Tor service. Both types of addresses can coexist on the same node.

Save the file and restart the Tor service. In linux:

`/etc/init.d/tor restart` or `sudo systemctl start tor` depending 
on the configuration of your system.

You will find the newly created address with:

```
sudo cat /var/lib/tor/var/lib/tor/lightningd-service_v2/hostname 
```
or
```
sudo cat /var/lib/tor/var/lib/tor/lightningd-service_v3/hostname 
```
in the 
case of a version 3 Tor address.

Now we are able to create:

* Non-persistent version 2 .onion address via auto service (temp-v2)

* Persistent version 2 and version 3 .onion addresseses (v2 and v3). 

Let's see how to use them.

### What do we support

| Case #  | IP Number     | Tor address               |Incoming / Outgoing Tor |
| ------- | ------------- | ------------------------- |-------------------------
| 1       | Public        | NO                        | Outgoing               |
| 2       | Public        | v2 [1]                    | Incoming [4]           |
| 3       | Public        | temp-v2 [2]               | Incoming               |
| 4       | Not Announced | v2                        | Incoming               |
| 5       | Not Announced | temp-v2                   | Incoming               |
| 6       | Public        | v3 [3] + temp-v2          | Incoming               |
| 7       | Not Announced | v3 + v2 + temp-v2         | Incoming               |
| 8       | Public        | NO                        | Outcoing socks5 .      |

NOTE:

1. v2: The Version 2 onion address is persistent across Tor service restarts. 
It is created when you create the [Tor Hidden Service](#Creation-of-an-hidden-service-for-a-persistent-onion-address).

2. temp-v2: The Version 2 onion address changes at each restart of the Tor service. 
A non-persistent .onion address is generated by accessing an [auto service](#creation-of-an-auto-service-for-non-persistent-onion-addresses).

3. All the v3 addresses referes to [.onion addresses version 3].

4. In all the "Incoming" use case, the node can also make "Outgoing" Tor 
connections (connect to a .onion address) by adding the 
`--proxy:127.0.0.1:9050` option.

#### Case 1 c-lightning has a public IP address and no Tor hidden service address, but can connect to an onion address via a Tor socks 5 proxy. 

Without a .onion address, the node won't be reachable through Tor by other 
nodes but it will always be able to `connect` to a Tor enabled node 
(outbound connections), passing the `connect` request through the Tor 
service socks5 proxy. When the Tor service starts it creates a socks5 
proxy which is by default at the address 127.0.0.1:9050.  

If the node is started  with the option `--proxy=127.0.0.1:9050` the node 
will be always able to connect to nodes with .onion address through the socks5 
proxy. 

**You can always add this option, also in the other use cases, to add outgoing 
Tor capabilities.**

If you want to `connect` to nodes ONLY via the Tor proxy, you have to add the 
`--always-use-proxy` option.

You can announce your public IP address through the usual method:

```
--bind-addr=internalIPAddress:port --announce-addr=externalIpAddress
```
if the node is into an internal network
```
--addr=externalIpAddress
```
if the node is not inside an internal network.

TIP: If you are unsure which of the two is suitable for you, find your internal 
and external address and see if they match.

In linux:

Discover your external IP address with: `curl ipinfo.io/ip`

and your internal IP Address with: `ip route get 1 | awk '{print $NF;exit}'`

If they match you can use the `--addr` command line option. 

#### Case #2 c-lightning has a public IP address and a fixed Tor hidden service address that is persistent, so that external users can connect to this node.

To have your external IP address and your .onion address announced, you use the
```
--bind-addr=yourInternalIPAddress:port --announce-addr=yourexternalIPAddress:port --announce-addr=your.onionAddress:port` 
```
option.

If you are not inside an internal network you can use 
```
--addr=yourIPAddress:port --announce-addr=your.onionAddress:port
```
your.onionAddress is the one created with the Tor hidden service ([see above](#creation-of-an-hidden-service-for-a-persistent-onion-address)). 
The port is the one indicated as the hidden service port. If the hidden service creation 
line is `HiddenServicePort 1234 127.0.0.1:9735` the .onion address will be reachable at 
the 1234 port (the global port).

It will be possible to connect to this node with:
```
lightning-cli connect nodeID .onionAddress globalPort 
```
through Tor where .onion address is in the form `xxxxxxxxxxxxxxxxxxxxxxxxxx.onion`, Or
```
lightning-cli connect nodeID yourexternalIPAddress Port
```
through Clearnet.

#### Case #3 c-lightning has a public IP address and a non-persisten Tor service address

In this case other nodes can connect to you via Clearnet or Tor.

To announce your IP address to the network, you add:
```
--bind-addr=internalAddress:port --announce-addr=yourExternalIPAddress
```
or `--addr=yourExternalIPAddress`if you are NOT on an internal network.

To get your non-persistent Tor address, add 
`--addr=autotor:127.0.0.1:9051` if you want to announce it or 
`--bind-addr=autotor:127.0.0.1:9051` if you don't want to announce it.

If the auto service is protected by password ([see above](#service-authenticated-by-password)) it is necessary to 
specify it with the option `--tor-service-password=yourpassword` (not the hash). 

You will obtain the generated non persisten .onion address by reading the results of the 
`lightning-cli getinfo` command. Other nodes will be able to connect to the 
.onion address through the 9735 port.

#### Case #4 c-lightning has no public IP address, but has a fixed Tor hidden service address that is persistent

Other nodes can connect to the announced .onion address created with the 
hidden service ([see above](#creation-of-an-hidden-service-for-a-persistent-onion-address)).

In this case In the `lightningd` command line you will specify:
```
--bind-addr=yourInternalIPAddress:port --announce-addr=your.onionAddress:port
```
or `--addr=your.onionAddress:port` if you are NOT on an internal network.

#### Case #5 c-lightning has no public IP address, and has no fixed Tor hidden service address

In this case it is difficult to track the node.
You specify just:
```
--bind-addr=yourInternalIPAddress:port --bind-addr=autotor:127.0.0.1:9051
```
In the `lightningd` command line.

Other nodes will not be able to `connect` to you unless you communicate them how to reach you.
You will find your .onion address with the command `lightning-cli getinfo` and the other nodes will 
be able to connect to it through the 9735 port.

#### Case #6 c-lightning has a public IP address and a fixed Tor V3 service address and a Tor V2 service address

You will be reachable via Clearnet, via Tor to the .onion V3 address and the 
.onion V2 address if this last is communicated to the node that wants to 
connect with our node.

to make your external IP address public you add: 
```
--bind-addr=yourInternalAddress:port --announce-addr=yourexternalIPAddress:port`. 
```
If the node is not on an internal network the option will be:
`--addr=yourexternalIPAddress:port`.

Once the .onion addresses have been created with the procedures [oulined above](#creation-of-an-hidden-service-for-a-persistent-onion-address), 
the node is already reachable at the .onion address.

To make your external .onion addresses public you add: 
```
--announce-addr=.onionAddressV2:port --announce-addr=.onionAddressV3:port 
```
to the options to publish your IP number.

#### Case #7 c-lightning has no public IP address, a fixed Tor V3 service address, a fixed Tor V2 service address and also a 3rd non persisten V2 address

External users can connect to this node by Tor V2 and V3 and a random V2 until next tor release, then also (V3 randomly).

The Persistent addresses can be created with the steps [outlined above](#creation-of-an-hidden-service-for-a-persistent-onion-address).

To create your non-persistent Tor address, add 
`--addr=autotor:127.0.0.1:9051` if you want to announce it or 
`--bind-addr=autotor:127.0.0.1:9051` if you don't want to announce it.

Also you must specify `--tor-service-password=yourpassword` (not the hash) to access the 
Tor service at 9051 If you have protected them with the password (no additional options if
they are protected with a cookie file. [See above](#creation-of-an-auto-service-for-non-persistent-onion-addresses)).

To make your external .onion address (V2 and V3) public you add: 
```
--bind-addr=yourInternalIPAddress:port --announce-addr=your.onionAddressV2:port --announce-addr=your.onionAddressV3:port
```
#### Case #8 	c-lightning has a public IP address and no Tor addresses

The external address is communicated by the 
```
--bind-addr=internalIPAddress:port --announce-addr=yourexternalIPAddress:port`
```
or `--addr=yourexternalIPAddress:port` if the node is not inside an internal network.

The node can connect to any V4/6 ip address via a IPV4/6 socks 5 proxy by specifing 
```
--proxy=127.0.0.1:9050 --always-use-proxy
```

## References

[The Tor project](https://www.torproject.org/)

[tor FAQ]: https://www.torproject.org/docs/faq.html.en#WhatIsTor

[Tor Hidden Service]: https://www.torproject.org/docs/onion-services.html.en

[.onion addresses version 3]: https://blog.torproject.org/we-want-you-test-next-gen-onion-services 
