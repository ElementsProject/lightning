lightning-createonion -- Low-level command to create a custom onion
===================================================================

SYNOPSIS
--------

**createonion** *hops* *assocdata* \[*session_key*\] \[*onion_size*\]

DESCRIPTION
-----------

The **createonion** RPC command allows the caller to create a custom onion
with custom payloads at each hop in the route. A custom onion can be used to
implement protocol extensions that are not supported by c-lightning directly.

The *hops* parameter is a JSON list of dicts, each specifying a node and the
payload destined for that node. The following is an example of a 3 hop onion:

```json
[
	{
		"pubkey": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
		"payload": "00000067000001000100000000000003e90000007b000000000000000000000000000000000000000000000000"
	}, {
		"pubkey": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
		"payload": "00000067000003000100000000000003e800000075000000000000000000000000000000000000000000000000"
	}, {
		"style": "legacy",
		"pubkey": "0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199",
		"payload": "00000067000003000100000000000003e800000075000000000000000000000000000000000000000000000000"
	}
]
```

The *hops* parameter is very similar to the result from `getroute` however it
needs to be modified slightly. The following is the `getroute` response from
which the above *hops* parameter was generated:

```json
[
	{
		"id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
		"channel": "103x2x1",
		"direction": 1,
		"msatoshi": 1002,
		"amount_msat": "1002msat",
		"delay": 21,
		"style": "legacy"
	}, {
		"id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
		"channel": "103x1x1",
		"direction": 0,
		"msatoshi": 1001,
		"amount_msat": "1001msat",
		"delay": 15,
		"style": "legacy"
	}, {
		"id": "0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199",
		"channel": "103x3x1",
		"direction": 0,
		"msatoshi": 1000,
		"amount_msat": "1000msat",
		"delay": 9,
		"style": "legacy"
	}
]
```

 - Notice that the payload in the *hops* parameter is the hex-encoded version
   of the parameters in the `getroute` response.
 - Except for the pubkey, the values are shifted left by one, i.e., the 1st
   payload in `createonion` corresponds to the 2nd set of values from `getroute`.
 - The final payload is a copy of the last payload sans `channel`

These rules are directly derived from the onion construction. Please refer
[BOLT 04][bolt04] for details and rationale.

The *assocdata* parameter specifies the associated data that the onion should
commit to. If the onion is to be used to send a payment later it MUST match
the `payment_hash` of the payment in order to be valid.

The optional *session_key* parameter can be used to specify a secret that is
used to generate the shared secrets used to encrypt the onion for each hop. It
should only be used for testing or if a specific shared secret is
important. If not specified it will be securely generated internally, and the
shared secrets will be returned.

The optional *onion_size* parameter specifies a size different from the default
payment onion (1300 bytes). May be used for custom protocols like trampoline
routing.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **onion** (hex): the onion packet (*onion_size* bytes)
- **shared_secrets** (array of hexs): one shared secret for each node in the *hops* parameter:
  - the shared secret with this hop (always 64 characters)
[comment]: # (GENERATE-FROM-SCHEMA-END)

EXAMPLE
-------

The following example is the result of calling *createonion* with the
above hops parameter:

```json
{
	"onion": "0003f3f80d2142b953319336d2fe4097[...✂...]6af33fcf4fb113bce01f56dd62248a9e5fcbbfba35c",
	"shared_secrets": [
		"88ce98c73e4d9293ab1797b0a913fe9bca0213a566252047d01b8af6da871f3e",
		"4474d296810e57bd460ef8b83d2e7d288321f8a99ff7686f87384699747bcfc4",
		"2a862e4123e01799a732be487fbce297f7dc7cc1467e410f18369cfee476adc2"
	]
}
```

The `onion` corresponds to 1366 hex-encoded bytes. Each shared secret consists
of 32 hex-encoded bytes. Both arguments can be passed on to **sendonion**.

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-sendonion(7), lightning-getroute(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[bolt04]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md
[comment]: # ( SHA256STAMP:a5a64325f4232f27bccbbe1c9fc62bfb602ba60c81f46a1ef2df25b06dac807e)
