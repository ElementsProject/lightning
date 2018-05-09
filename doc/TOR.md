HOWTO USE TOR WITH C-LIGHTNING

what do we support

1 	c-lightning has a public IP address and no TOR hidden service address,
	but can connect to an onion address via a TOR socks 5 proxy.

2 	c-lightning has a public IP address and a fixed TOR hidden service address that is persistent
	so that external users can connect to this node.

3 	c-lightning has a public IP address and not fixed TOR service address that (changes at each restart
	and that vanish at restart of tor)
	so that external users can connect to this node by TOR and IP

4 	c-lightning has no public IP address, but has a fixed TOR hidden service address that is persistent
	so that external users can connect to this node.

5 	c-lightning has no public IP address, and has no fixed TOR hidden service address
	(changes at each restart and vanish at restart of tor) to make it harder to track this node.

6	c-lightning has a public IP address and a fixed TOR V3 service address and a TOR V2 service address
	that (changes at each restart and that vanish at restart of tor)
	so that external users can connect to this node by TOR V2 and V3 and IP

7	c-lightning has nop public IP address and a fixed TOR V3 service address and fixed TOR V2 service  address
	a 3rd V2 address that (changes at each restart and that vanish at restart of tor)
	so that external users can connect to this node by TOR V2 and V3 and a random V2 until next tor release then also (V3 randomly)

8 	c-lightning has a public IP address and no TOR hidden service address,
	but can connect to any V4/6 ip address via a IPV4/6 socks 5 proxy.


to use tor you have to have tor installed an running.

i.e.
sudo apt install tor
/etc/init.d/tor start

if new to tor you might not change the default setting
# The safe default with minimal harassment (See tor FAQ)
ExitPolicy reject *:* # no exits allowed

this does not effect c-ln connect listen etc.
it will only prevent that you become a full exitpoint
Only enable this if you are sure about the implications.


if you want an auto service created
edit the torconfig file /etc/tor/torrc

set
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1

or create a password with

cmdline
tor --hash-password yourepassword

this returns an line like
16:533E3963988E038560A8C4EE6BBEE8DB106B38F9C8A7F81FE38D2A3B1F

put this in the /etc/tor/torrc file

i.e.
HashedControlPassword 16:533E3963988E038560A8C4EE6BBEE8DB106B38F9C8A7F81FE38D2A3B1F

save
and
/etc/init.d/tor restart

then you can use c-lightning with following options

--tor-service-password=yourpassword to access the tor service at 9051

--proxy=127.0.0.1:9050 : set the Tor proxy to use

or the password for the service if cookiefile is not accessable

--announce-addr=autotor:<torservice> : try to generate an temp V2 onion addr.

NOTE if --always-use-proxy set all traffic will be rooted over the proxy, or if no non-TOR addresses are announced.

you can also set a fixed onion addr by option
--addr=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion  (V2 or V3 is allowed)

this addr can be created by

HiddenServiceDir /var/lib/tor/bitcoin-service_v2/
HiddenServiceVersion 2
HiddenServicePort 8333 127.0.0.1:8333


HiddenServiceDir /var/lib/tor/other_hidden_service_v3/
HiddenServiceVersion 3
HiddenServicePort 9735 127.0.0.1:9735

in /etc/tor/torrc

the addr for
the --addr option

you find after /etc/init.d/tor restart

i.e.
in /var/lib/tor/other_hidden_service_v3/hostname


to see your onion addr use
cli/lightning-cli getinfo

some examples:

sudo lightningd/lightningd --network=testnet --bind-addr=127.0.0.1:1234
--proxy=127.0.0.1:9050 --addr=autotor:127.0.0.1:9051

this will try to generate an V2 auto hidden-service by reading the tor cookie and
also create local ipaddr at port 1234
so the node is accessableby connect peerid xxxxxxxxxxxxxxxx.onion 9735
or local by connect ID 127.0.0.1 1234

lightningd/lightningd --network=testnet --bind-addr=127.0.0.1
--proxy=127.0.0.1:9050 --addr=xxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion:1234

this will use the hidden-service set by /etc/tor/torrc and use the hidden service
so the node is  accessable by connect peerid xxxxxxxxxxxxxxxxxxxxxxxx.onion 1234
or
lightningd/lightningd --network=testnet --bind-addr=127.0.0.1:1234
--proxy=127.0.0.1:9050 --addr=xxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion:1234
this will use the hidden-service set by /etc/tor/torrc and use the hidden service
so the node is only accessable by connect peerid xxxxxxxxxxxxxxxxxxxxxxxonion 1234

for connects you can use
i.e cli/lightning-cli connect peerID xxxxxxxxxxxxxxxxxxxxxxx.onion 1234



