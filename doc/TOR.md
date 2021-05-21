# Setting up TOR with c-lightning

To use any Tor features with c-lightning you must have Tor installed and running.

Note that [Tor v2 onion services are deprecated since mid-2020](https://blog.torproject.org/v2-deprecation-timeline)
and that C-lightning deprecated their support since mid-2021.

You can check your installed Tor version with `tor --version` or `sudo tor --version`

If Tor is not installed you can install it on Debian based Linux systems (Ubuntu, Debian, etc) with the following command:

```bash
sudo apt install tor
```
then `/etc/init.d/tor start` or `sudo systemctl start tor` depending
on your system configuration.

Most default setting should be sufficient.

To keep a safe configuration for minimal harassment (See [Tor FAQ])
just check that this line is present in the Tor config file `/etc/tor/torrc`:

`ExitPolicy reject *:* # no exits allowed`

This does not affect c-lightning connect, listen, etc..
It will only prevent your node from becoming a Tor exit node.
Only enable this if you are sure about the implications.

If you don't want to create .onion addresses this should be enough.

There are several ways by which a c-lightning node can accept or make connections over Tor.

The node can be reached over Tor by connecting to its .onion address.

To provide the node with a .onion address you can:

* create a **non-persistent** address with an auto service or

* create a **persistent** address with a hidden service.

### Quick Start On Linux

It is easy to create a single persistent Tor address and not announce a public IP.
This is ideal for most setups where you have an ISP-provided router connecting your
Internet to your local network and computer, as it does not require a stable
public IP from your ISP (which might not give one to you for free), nor port
forwarding (which can be hard to set up for random cheap router models).
Tor provides NAT-traversal for free, so even if you or your ISP has a complex
network between you and the Internet, as long as you can use Tor you can
be connected to.

On most Linux distributions, making a standard installation of `tor` will
automatically set it up to have a SOCKS5 proxy at port 9050.
As well, you have to set up the Tor Control Port.
On most Linux distributions there will be commented-out settings below in the
`/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```

Uncomment those in, then restart `tor` (usually `systemctl restart tor`  or
`sudo systemctl restart tor` on most SystemD-based systems, including recent
Debian and Ubuntu, or just restart the entire computer if you cannot figure
it out).

On some systems (such as Arch Linux), you may also need to add the following
setting:

```
DataDirectoryGroupReadable 1
```

You also need to make your user a member of the Tor group.
"Your user" here is whatever user will run `lightningd`.
On Debian-derived systems, the Tor group will most likely be `debian-tor`.
You can try listing all groups with the below command, and check for a
`debian-tor` or `tor` groupname.

```
getent group | cut -d: -f1 | sort
```

Alternately, you could check the group of the cookie file directly.
Usually, on most Linux systems, that would be `/run/tor/control.authcookie`:

```
stat -c '%G' /run/tor/control.authcookie
```

Once you have determined the `${TORGROUP}` and selected the
`${LIGHTNINGUSER}` that will run `lightningd`, run this as root:

```
usermod -a -G ${TORGROUP} ${LIGHTNINGUSER}
```

Then restart the computer (logging out and logging in again should also
work).
Confirm that `${LIGHTNINGUSER}` is in `${TORGROUP}` by running the
`groups` command as `${LIGHTNINGUSER}` and checking `${TORGROUP}` is listed.

If the `/run/tor/control.authcookie` exists in your system, then log in as
the user that will run `lightningd` and check this command:

```
cat /run/tor/control.authcookie > /dev/null
```

If the above prints nothing and returns, then C-Lightning "should" work
with your Tor.
If it prints an error, some configuration problem will likely prevent
C-Lightning from working with your Tor.

Then make sure these are in your `${LIGHTNING_DIR}/config` or other C-Lightning configuration
(or prepend `--` to each of them and add them to your `lightningd` invocation
command line):

```
proxy=127.0.0.1:9050
bind-addr=127.0.0.1:9735
addr=statictor:127.0.0.1:9051
always-use-proxy=true
```

1.  `proxy` informs C-Lightning that you have a SOCKS5 proxy at port 9050.
    C-Lightning will assume that this is a Tor proxy, port 9050 is the
    default in most Linux distributions; you can double-check `/etc/tor/torrc`
    for a `SocksPort` entry to confirm the port number.
2.  `bind-addr` informs C-Lightning to bind itself to port 9735.
    This is needed for the subsequent `statictor` to work.
    9735 is the normal Lightning Network port, so this setting may already be present.
    If you add a second `bind-addr=...` you may get errors, so choose this new one
    or keep the old one, but don't keep both.
    This has to appear before any `statictor:` setting.
3.  `addr=statictor:` informs C-Lightning that you want to create a persistent
    hidden service that is based on your node private key.
    This informs C-Lightning as well that the Tor Control Port is 9051.
    You can also use `bind-addr=statictor:` instead to not announce the
    persistent hidden service, but if anyone wants to make a channel with
    you, you either have to connect to them, or you have to reveal your
    address to them explicitly (i.e. autopilots and the like will likely
    never connect to you).
4.  `always-use-proxy` informs C-Lightning to always use Tor even when
    connecting to nodes with public IPs.
    You can set this to `false` or remove it,
    if you are not privacy-conscious **and** find Tor is too slow for you.

### Tor Browser and Orbot

It is possible to not install Tor on your computer, and rely on just
Tor Browser.
Tor Browser will run a built-in Tor instance, but with the proxy at port
9150 and the control port at 9151
(the normal Tor has, by default, the proxy at port 9050 and the control
port at 9051).
The mobile Orbot uses the same defaults as Tor Browser (9150 and 9151).

You can then use these settings for C-Lightning:

```
proxy=127.0.0.1:9150
bind-addr=127.0.0.1:9735
addr=statictor:127.0.0.1:9151
always-use-proxy=true
```

You will have to run C-Lightning after launching Tor Browser or Orbot,
and keep Tor Browser or Orbot open as long as C-Lightning is running,
but this is a setup which allows others to connect and fund channels
to you, anywhere (no port forwarding! works wherever Tor works!), and
you do not have to do anything more complicated than download and
install Tor Browser.
This may be useful for operating system distributions that do not have
Tor in their repositories, assuming we can ever get C-Lightning running
on those.

### Detailed Discussion

#### Creation of an auto service for non-persistent .onion addresses

To provide the node a non-persistent .onion address it
is necessary to access the Tor auto service. These types of addresses change
each time the Tor service is restarted.

*NOTE:If the node is required to be reachable only by **persistent** .onion addresses, this
part can be skipped and it is necessary to set up a hidden service with the steps
outlined in the next section.*

To create and use the auto service follow these steps:

Edit the Tor config file `/etc/tor/torrc`

You can configure the service authenticated by cookie or by password:

##### Service authenticated by cookie
Add the following lines in the `/etc/tor/torrc` file:

````
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
````

##### Service authenticated by password

Alternatively, you can set the authentication
to the service with a password by following these steps:

1. Create a hash of your password with
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

Save the file and restart the Tor service. In linux:

`/etc/init.d/tor restart` or `sudo systemctl start tor` depending
on the configuration of your system.

The auto service is used by adding `--addr=autotor:127.0.0.1:9051` if you
want the address to be public or `--bind-addr=autotor:127.0.0.1:9051` if you
don't want to publish it.

In the case where the auto service is authenticated through a password, it will
be necessary to add the option `--tor-service-password=yourpassword` (not the hash).

The created non-persistent .onion address will be shown by the `lightning-cli getinfo`
command. The other nodes will be able to `connect` to this .onion address through the
9735 port.

#### Creation of a hidden service for a persistent .onion address

To have a persistent .onion address other nodes can connect to, it
is necessary to set up a [Tor Hidden Service].

*NOTE: In the case where only non-persistent addresses are required,
you don't have to create the hidden service and you can skip this part.*

##### Automatic persistent .onion address

It is possible to generate persistent .onion addresses automatically.

Add the following lines in the `/etc/tor/torrc` file
(you might already have done this if for example you connected Bitcoin
over Tor):

````
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
````

Then you can use `--addr=statictor:127.0.0.1:9051` instead of
`--announce-addr=.onionAddressV3`.
By default V3 onion addresses are generated.

Note that you have to specify a `--bind-addr` first before using
`--addr=statictor:`.
Generally `--bind-addr=127.0.0.1:9735` should work fine.

You can also have multiple persistent .onion addresses
by adding `/torblob=BLOB`, where `BLOB` is 32 to 64 ***random***
bytes of text.
Note that this blob will be used to derive the secret key behind
the .onion address and you should keep the blob secret otherwise
anyone who steals it can spoof your .onion address and block
incoming data to your node via this .onion address.
You can then specify multiple `statictor:` options with different
`BLOB`s.

However, even if you have multiple persistent addresses, you can
only announce up to one onion service (v3).
This is a limitation of the BOLT spec.
It is still possible for other nodes to contact you by those
other hidden services.

Finally, the default external port number for the autogenerated
persistent .onion address will be 9735, but you can change this by
adding `/torport=9999` to change the external port for the .onion
address.

##### Explicit Control

If you want to create a version 3 address, you must also add `HiddenServiceVersion 3` so
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
sudo cat /var/lib/tor/lightningd-service_v3/hostname
```

Now you are able to create:

* Persistent version 3 hidden services.

Let's see how to use them.

### What do we support

| Case #  | IP Number     | Hidden service            |Incoming / Outgoing Tor |
| ------- | ------------- | ------------------------- |-------------------------
| 1       | Public        | NO                        | Outgoing               |
| 6       | Public        | v3                        | Incoming [1]           |
| 7       | Not Announced | v3                        | Incoming               |
| 8       | Public        | NO                        | Outcoing socks5 .      |

NOTE:

1. In all the "Incoming" use case, the node can also make "Outgoing" Tor
connections (connect to a .onion address) by adding the
`--proxy=127.0.0.1:9050` option.

#### Case #1 c-lightning has a public IP address and no Tor hidden service address, but can connect to an onion address via a Tor socks 5 proxy.

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
`--always-use-proxy=true` option.

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
or
```
--bind-addr=yourInternalIPAddress:port --announce-addr=yourexternalIPAddress:port --addr=statictor:127.0.0.1:9051`
```
options.

If you are not inside an internal network you can use
```
--addr=yourIPAddress:port --announce-addr=your.onionAddress:port
```
or
```
--addr=yourIPAddress:port --addr=statictor:127.0.0.1:9051
```

your.onionAddress is the one created with the Tor hidden service ([see above](#creation-of-an-hidden-service-for-a-persistent-onion-address)).
The port is the one indicated as the hidden service port. If the hidden service creation
line is `HiddenServicePort 1234 127.0.0.1:9735` the .onion address will be reachable at
the 1234 port (the global port).

For `statictor` the `127.0.0.1` is your computer, and `9051` is the
Tor Control Port you set up in the `/etc/tor/torrc` file.

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
--bind-addr=yourInternalIPAddress:port --addr=autotor:127.0.0.1:9051
```
In the `lightningd` command line.

Other nodes will not be able to `connect` to you unless you communicate them how to reach you.
You will find your .onion address with the command `lightning-cli getinfo` and the other nodes will
be able to connect to it through the 9735 port.

#### Case #6 c-lightning has a public IP address and a fixed Tor v3 hidden service

You will be reachable via Clearnet, via Tor to the .onion if it is communicated to the node that wants to
connect with our node.

To make your external IP address public you add:
```
--bind-addr=yourInternalAddress:port --announce-addr=yourexternalIPAddress:port`.
```
If the node is not on an internal network the option will be:
`--addr=yourexternalIPAddress:port`.

Once the .onion addresses have been created with the procedures [oulined above](#creation-of-an-hidden-service-for-a-persistent-onion-address),
the node is already reachable at the .onion address.

To make your external hidden service public you add:
```
--announce-addr=.onionAddressV3:port
```
to the options to publish your IP number.

#### Case #7 c-lightning has no public IP address, a fixed Tor V3 service address

The Persistent addresses can be created with the steps [outlined above](#creation-of-an-hidden-service-for-a-persistent-onion-address).

To create your non-persistent Tor address, add
`--addr=autotor:127.0.0.1:9051` if you want to announce it or
`--bind-addr=autotor:127.0.0.1:9051` if you don't want to announce it.

Also you must specify `--tor-service-password=yourpassword` (not the hash) to access the
Tor service at 9051 If you have protected them with the password (no additional options if
they are protected with a cookie file. [See above](#creation-of-an-auto-service-for-non-persistent-onion-addresses)).

To make your external onion service public you add:
```
--bind-addr=yourInternalIPAddress:port --announce-addr=your.onionAddressV3:port
```
#### Case #8 	c-lightning has a public IP address and no Tor addresses

The external address is communicated by the
```
--bind-addr=internalIPAddress:port --announce-addr=yourexternalIPAddress:port`
```
or `--addr=yourexternalIPAddress:port` if the node is not inside an internal network.

The node can connect to any V4/6 ip address via a IPV4/6 socks 5 proxy by specifing
```
--proxy=127.0.0.1:9050 --always-use-proxy=true
```

## References

[The Tor project](https://www.torproject.org/)

[tor FAQ]: https://www.torproject.org/docs/faq.html.en#WhatIsTor

[Tor Hidden Service]: https://www.torproject.org/docs/onion-services.html.en

[.onion addresses version 3]: https://blog.torproject.org/we-want-you-test-next-gen-onion-services
