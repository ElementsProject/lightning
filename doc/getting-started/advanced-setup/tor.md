---
title: "Using Tor"
slug: "tor"
hidden: false
createdAt: "2023-01-25T10:55:50.059Z"
updatedAt: "2023-02-21T13:30:33.294Z"
---
To use any Tor features with Core Lightning you must have Tor installed and running.

Note that we only support Tor v3: you can check your installed Tor version with `tor --version` or `sudo tor --version`

If Tor is not installed you can install it on Debian based Linux systems (Ubuntu, Debian, etc) with the following command:

```shell
sudo apt install tor
```



then `/etc/init.d/tor start` or `sudo systemctl enable --now tor` depending on your system configuration.

Most default setting should be sufficient.

To keep a safe configuration for minimal harassment (See [Tor FAQ](https://www.torproject.org/docs/faq.html.en#WhatIsTor)) just check that this line is present in the Tor config file `/etc/tor/torrc`:

`ExitPolicy reject *:* # no exits allowed`

This does not affect Core Lightning connect, listen, etc. It will only prevent your node from becoming a Tor exit node. Only enable this if you are sure about the implications.

If you don't want to create .onion addresses this should be enough.

There are several ways by which a Core Lightning node can accept or make connections over Tor. The node can be reached over Tor by connecting to its .onion address.

To provide the node with a .onion address you can:

- create a **non-persistent** address with an auto service or

- create a **persistent** address with a hidden service.

### Quick Start On Linux

It is easy to create a single persistent Tor address and not announce a public IP. This is ideal for most setups where you have an ISP-provided router connecting your Internet to your local network and computer, as it does not require a stable public IP from your ISP (which might not give one to you for free), nor port forwarding (which can be hard to set up for random cheap router models). Tor provides NAT-traversal for free, so even if you or your ISP has a complex  
network between you and the Internet, as long as you can use Tor you can be connected to.

> 📘 
> 
> Core Lightning also support IPv4/6 address discovery behind NAT routers.

For this to work you need to forward the default TCP port 9735 to your node. In this case you don't need TOR to punch through your firewall. IP discovery is only active if no other addresses are announced. This usually has the benefit of quicker and more stable connections but does not  
offer additional privacy.

On most Linux distributions, making a standard installation of `tor` will automatically set it up to have a SOCKS5 proxy at port 9050. As well, you have to set up the Tor Control Port. On most Linux distributions there will be commented-out settings below in the  
`/etc/tor/torrc`:

```shell
ControlPort 9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
CookieAuthFileGroupReadable 1
```



Uncomment those in, then restart `tor` (usually `systemctl restart tor`  or  
`sudo systemctl restart tor` on most SystemD-based systems, including recent Debian and Ubuntu, or just restart the entire computer if you cannot figure it out).

On some systems (such as Arch Linux), you may also need to add the following setting:

```shell
DataDirectoryGroupReadable 1
```



You also need to make your user a member of the Tor group.  
"Your user" here is whatever user will run `lightningd`. On Debian-derived systems, the Tor group will most likely be `debian-tor`. You can try listing all groups with the below command, and check for a `debian-tor` or `tor` groupname.

```shell
getent group | cut -d: -f1 | sort
```



Alternately, you could check the group of the cookie file directly.  
Usually, on most Linux systems, that would be `/run/tor/control.authcookie`:

```shell
stat -c '%G' /run/tor/control.authcookie
```



Once you have determined the `${TORGROUP}` and selected the  
`${LIGHTNINGUSER}` that will run `lightningd`, run this as root:

```shell
usermod -a -G ${TORGROUP} ${LIGHTNINGUSER}
```



Then restart the computer (logging out and logging in again should also work).  
Confirm that `${LIGHTNINGUSER}` is in `${TORGROUP}` by running the `groups` command as `${LIGHTNINGUSER}` and checking `${TORGROUP}` is listed.

If the `/run/tor/control.authcookie` exists in your system, then log in as the user that will run `lightningd` and check this command:

```shell
cat /run/tor/control.authcookie > /dev/null
```



If the above prints nothing and returns, then Core Lightning "should" work with your Tor.  
If it prints an error, some configuration problem will likely prevent Core Lightning from working with your Tor.

Then make sure these are in your `${LIGHTNING_DIR}/config` or other Core Lightning configuration (or prepend `--` to each of them and add them to your `lightningd` invocation  
command line):

```shell
proxy=127.0.0.1:9050
bind-addr=127.0.0.1:9735
addr=statictor:127.0.0.1:9051
always-use-proxy=true
```



1. `proxy` informs Core Lightning that you have a SOCKS5 proxy at port 9050.  
   Core Lightning will assume that this is a Tor proxy, port 9050 is the default in most Linux distributions; you can double-check `/etc/tor/torrc` for a `SocksPort` entry to confirm the port number.
2. `bind-addr` informs Core Lightning to bind itself to port 9735.  
   This is needed for the subsequent `statictor` to work.  
   9735 is the normal Lightning Network port, so this setting may already be present.  
   If you add a second `bind-addr=...` you may get errors, so choose this new one or keep the old one, but don't keep both.  
   This has to appear before any `statictor:` setting.
3. `addr=statictor:` informs Core Lightning that you want to create a persistent hidden service that is based on your node private key.  
   This informs Core Lightning as well that the Tor Control Port is 9051. You can also use `bind-addr=statictor:` instead to not announce the persistent hidden service, but if anyone wants to make a channel with you, you either have to connect to them, or you have to reveal your address to them explicitly (i.e. autopilots and the like will likely never connect to you).
4. `always-use-proxy` informs Core Lightning to always use Tor even when connecting to nodes with public IPs. You can set this to `false` or remove it, if you are not privacy-conscious **and** find Tor is too slow for you.

### Tor Browser and Orbot

It is possible to not install Tor on your computer, and rely on just Tor Browser.  
Tor Browser will run a built-in Tor instance, but with the proxy at port 9150 and the control port at 9151 (the normal Tor has, by default, the proxy at port 9050 and the control  
port at 9051). The mobile Orbot uses the same defaults as Tor Browser (9150 and 9151).

You can then use these settings for Core Lightning:

```shell
proxy=127.0.0.1:9150
bind-addr=127.0.0.1:9735
addr=statictor:127.0.0.1:9151
always-use-proxy=true
```



You will have to run Core Lightning after launching Tor Browser or Orbot, and keep Tor Browser or Orbot open as long as Core Lightning is running, but this is a setup which allows others to connect and fund channels to you, anywhere (no port forwarding! works wherever Tor works!), and you do not have to do anything more complicated than download and install Tor Browser.  
This may be useful for operating system distributions that do not have Tor in their repositories, assuming we can ever get Core Lightning running on those.

### Detailed Discussion

#### Three Ways to Create .onion Addresses for Core Lightning

1. You can configure Tor to create an onion address for you, and tell Core Lightning to use that address
2. You can have Core Lightning tell Tor to create a new onion address every time
3. You can configure Core Lightning to tell Tor to create the same onion address every time it starts up

#### Tor-Created .onion Address

Having Tor create an onion address lets you run other services (e.g. a web server) at that same address, and you just tell that address to Core Lightning and it doesn't have to talk to the Tor server at all.

Put the following in your `/etc/tor/torrc` file:

```shell
HiddenServiceDir /var/lib/tor/lightningd-service_v3/
HiddenServiceVersion 3
HiddenServicePort 1234 127.0.0.1:9735
```



The hidden lightning service  will be reachable at port 1234 (global port) of the .onion address, which will be created at the restart of the Tor service.  Both types of addresses can coexist on the same node.

Save the file and restart the Tor service. In linux:

`/etc/init.d/tor restart` or `sudo systemctl restart tor` depending on the configuration of your system.

You will find the newly created address (myaddress.onion) with:

```shell
sudo cat /var/lib/tor/lightningd-service_v3/hostname
```



Now you need to tell Core Lightning to advertize that onion hostname and port, by placing `announce-addr=myaddress.onion` in your lightning config.

#### Letting Core Lightning Control Tor

To have Core Lightning control your Tor addresses, you have to tell Tor to accept control commands from Core Lightning, either by using a cookie, or a password.

##### Service authenticated by cookie

This tells Tor to create a cookie file each time: lightningd will have to be in the same group as tor (e.g. debian-tor): you can look at `/run/tor/control.authcookie` to check the group name.

Add the following lines in the `/etc/tor/torrc` file:

```shell
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```



Save the file and restart the Tor service.

##### Service authenticated by password

This tells Tor to allow password access: you also need to tell lightningd what the password is.

Create a hash of your password with

```shell
tor --hash-password yourpassword
```



This returns a line like

`16:533E3963988E038560A8C4EE6BBEE8DB106B38F9C8A7F81FE38D2A3B1F`

Put these lines in the `/etc/tor/torrc` file:

```shell
ControlPort 9051
HashedControlPassword 16:533E3963988E038560A8C4EE6BBEE8DB106B38F9C8A7F81FE38D2A3B1F
```



Save the file and restart the Tor service.

Put `tor-service-password=yourpassword` (not the hash) in your lightning configuration file.

##### Core Lightning Creating Persistent Hidden Addresses

This is usually better than transient addresses, as nodes won't have to wait for gossip propagation to find out your new address each time you restart.

Once you've configured access to Tor as described above, you need to add _two_ lines in your lightningd config file:

1. A local address which lightningd can tell Tor to connect to when connections come in, e.g. `bind-addr=127.0.0.1:9735`.
2. After that, a `addr=statictor:127.0.0.1:9051` to tell Core Lightning to set up and announce a Tor onion address (and tell Tor to send connections to our real address, above).

You can use `bind-addr` if you want to set up the onion address and not announce it to the world for some reason.

You may add more `addr` lines if you want to advertise other addresses.

There is an older method, called "autotor" instead of "statictor" which creates a different Tor address on each restart, which is usually not very helpful; you need to use lightning-cli getinfo\` to see what address it is currently using, and other peers need to wait for fresh gossip messages if you announce it, before they can connect.

### What do we support

| Case # | IP Number     | Hidden service          | Incoming / Outgoing Tor |
| ------ | ------------- | ----------------------- | ----------------------- |
| 1      | Public        | NO                      | Outgoing                |
| 2      | Public        | FIXED BY TOR            | Incoming [1]            |
| 3      | Public        | FIXED BY CORE LIGHTNING | Incoming [1]            |
| 4      | Not Announced | FIXED BY TOR            | Incoming [1]            |
| 5      | Not Announced | FIXED BY CORE LIGHTNING | Incoming [1]            |

> 📘 
> 
> In all the "Incoming" use case, the node can also make "Outgoing" Tor  
> connections (connect to a .onion address) by adding the `proxy=127.0.0.1:9050` option.

#### Case #1: Public IP address and no Tor address, but can connect to Tor addresses

Without a .onion address, the node won't be reachable through Tor by other nodes but it will always be able to `connect` to a Tor enabled node (outbound connections), passing the `connect` request through the Tor service socks5 proxy. When the Tor service starts it creates a socks5 proxy which is by default at the address 127.0.0.1:9050.

If the node is started with the option `proxy=127.0.0.1:9050` the node will be always able to connect to nodes with .onion address through the socks5 proxy.

**You can always add this option, also in the other use cases, to add outgoing  
Tor capabilities.**

If you want to `connect` to nodes ONLY via the Tor proxy, you have to add the `always-use-proxy=true` option (though if you only advertize Tor addresses, we also assume you want to always use the proxy).

You can announce your public IP address through the usual method: if your node is in an internal network:

```shell
bind-addr=internalIPAddress:port
announce-addr=externalIpAddress
```



or if it has a public IP address:

```shell
addr=externalIpAddress
```



> 📘 
> 
> If you are unsure which of the two is suitable for you, find your internal and external address and see if they match.

In linux:

Discover your external IP address with: `curl ipinfo.io/ip` and your internal IP Address with: `ip route get 1 | awk '{print $NF;exit}'`.

If they match you can use the `--addr` command line option.

#### Case #2: Public IP address, and a fixed Tor address in torrc

Other nodes can connect to you entirely over Tor, and the Tor address doesn't change every time you restart.

You simply tell Core Lightning to advertize both addresses (you can use `sudo cat /var/lib/tor/lightningd-service_v3/hostname` to get your Tor-assigned onion address).

If you have an internal IP address:

```shell
bind-addr=yourInternalIPAddress:port
announce-addr=yourexternalIPAddress:port
announce-addr=your.onionAddress:port
```



Or an external address:

```shell
addr=yourIPAddress:port
announce-addr=your.onionAddress:port
```



#### Case #3: Public IP address, and a fixed Tor address set by Core Lightning

Other nodes can connect to you entirely over Tor, and the Tor address doesn't change every time you restart.

See "Letting Core Lightning Control Tor" for how to get Core Lightning talking to Tor.

If you have an internal IP address:

```shell
bind-addr=yourInternalIPAddress:port
announce-addr=yourexternalIPAddress:port
addr=statictor:127.0.0.1:9051
```



Or an external address:

```shell
addr=yourIPAddress:port
addr=statictor:127.0.0.1:9051
```



#### Case #4: Unannounced IP address, and a fixed Tor address in torrc

Other nodes can only connect to you over Tor.

You simply tell Core Lightning to advertize the Tor address (you can use `sudo cat /var/lib/tor/lightningd-service_v3/hostname` to get your Tor-assigned onion address).

```
announce-addr=your.onionAddress:port
proxy=127.0.0.1:9050
always-use-proxy=true
```



#### Case #4: Unannounced IP address, and a fixed Tor address set by Core Lightning

Other nodes can only connect to you over Tor.

See "Letting Core Lightning Control Tor" for how to get Core Lightning  
talking to Tor.

```
addr=statictor:127.0.0.1:9051
proxy=127.0.0.1:9050
always-use-proxy=true
```



## References

- [Configuring your node](doc:configuration) section (or [`lightningd-config`](ref:lightningd-config) manual page) covers the various address cases in detail.
- [The Tor project](https://www.torproject.org/)
- [Tor FAQ](https://www.torproject.org/docs/faq.html.en#WhatIsTor)
- [Tor Hidden Service](https://www.torproject.org/docs/onion-services.html.en)
- [.onion addresses version 3](https://blog.torproject.org/we-want-you-test-next-gen-onion-services)