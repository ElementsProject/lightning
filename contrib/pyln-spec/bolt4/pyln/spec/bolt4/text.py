desc = "BOLT #4: Onion Routing Protocol"
text = """# BOLT #4: Onion Routing Protocol

## Overview

This document describes the construction of an onion routed packet that is
used to route a payment from an _origin node_ to a _final node_. The packet
is routed through a number of intermediate nodes, called _hops_.

The routing schema is based on the [Sphinx][sphinx] construction and is
extended with a per-hop payload.

Intermediate nodes forwarding the message can verify the integrity of
the packet and can learn which node they should forward the
packet to. They cannot learn which other nodes, besides their
predecessor or successor, are part of the packet's route; nor can they learn
the length of the route or their position within it. The packet is
obfuscated at each hop, to ensure that a network-level attacker cannot
associate packets belonging to the same route (i.e. packets belonging
to the same route do not share any correlating information). Notice that this
does not preclude the possibility of packet association by an attacker
via traffic analysis.

The route is constructed by the origin node, which knows the public
keys of each intermediate node and of the final node. Knowing each node's public key
allows the origin node to create a shared secret (using ECDH) for each
intermediate node and for the final node. The shared secret is then
used to generate a _pseudo-random stream_ of bytes (which is used to obfuscate
the packet) and a number of _keys_ (which are used to encrypt the payload and
compute the HMACs). The HMACs are then in turn used to ensure the integrity of
the packet at each hop.

Each hop along the route only sees an ephemeral key for the origin node, in
order to hide the sender's identity. The ephemeral key is blinded by each
intermediate hop before forwarding to the next, making the onions unlinkable
along the route.

This specification describes _version 0_ of the packet format and routing
mechanism.

A node:
  - upon receiving a higher version packet than it implements:
    - MUST report a route failure to the origin node.
    - MUST discard the packet.

# Table of Contents

  * [Conventions](#conventions)
  * [Key Generation](#key-generation)
  * [Pseudo Random Byte Stream](#pseudo-random-byte-stream)
  * [Packet Structure](#packet-structure)
    * [Legacy HopData Payload Format](#legacy-hop_data-payload-format)
    * [TLV Payload Format](#tlv_payload-format)
    * [Basic Multi-Part Payments](#basic-multi-part-payments)
  * [Accepting and Forwarding a Payment](#accepting-and-forwarding-a-payment)
    * [Payload for the Last Node](#payload-for-the-last-node)
    * [Non-strict Forwarding](#non-strict-forwarding)
  * [Shared Secret](#shared-secret)
  * [Blinding Ephemeral Keys](#blinding-ephemeral-keys)
  * [Packet Construction](#packet-construction)
  * [Packet Forwarding](#packet-forwarding)
  * [Filler Generation](#filler-generation)
  * [Returning Errors](#returning-errors)
    * [Failure Messages](#failure-messages)
    * [Receiving Failure Codes](#receiving-failure-codes)
  * [Test Vector](#test-vector)
    * [Returning Errors](#returning-errors)
  * [References](#references)
  * [Authors](#authors)

# Conventions

There are a number of conventions adhered to throughout this document:

 - HMAC: the integrity verification of the packet is based on Keyed-Hash
   Message Authentication Code, as defined by the [FIPS 198
   Standard][fips198]/[RFC 2104][RFC2104], and using a `SHA256` hashing
   algorithm.
 - Elliptic curve: for all computations involving elliptic curves, the Bitcoin
   curve is used, as specified in [`secp256k1`][sec2]
 - Pseudo-random stream: [`ChaCha20`][rfc8439] is used to generate a
   pseudo-random byte stream. For its generation, a fixed 96-bit null-nonce
   (`0x000000000000000000000000`) is used, along with a key derived from a shared
   secret and with a `0x00`-byte stream of the desired output size as the
   message.
 - The terms _origin node_ and _final node_ refer to the initial packet sender
   and the final packet recipient, respectively.
 - The terms _hop_ and _node_ are sometimes used interchangeably, but a _hop_
   usually refers to an intermediate node in the route rather than an end node.
        _origin node_ --> _hop_ --> ... --> _hop_ --> _final node_
 - The term _processing node_ refers to the specific node along the route that is
   currently processing the forwarded packet.
 - The term _peers_ refers only to hops that are direct neighbors (in the
   overlay network): more specifically, _sending peers_ forward packets
   to _receiving peers_.
 - Each hop in the route has a variable length `hop_payload`, or a fixed-size
   legacy `hop_data` payload.
    - The legacy `hop_data` is identified by a single `0x00`-byte prefix
    - The variable length `hop_payload` is prefixed with a `bigsize` encoding
      the length in bytes, excluding the prefix and the trailing HMAC.

# Key Generation

A number of encryption and verification keys are derived from the shared secret:

 - _rho_: used as key when generating the pseudo-random byte stream that is used
   to obfuscate the per-hop information
 - _mu_: used during the HMAC generation
 - _um_: used during error reporting
 - _pad_: use to generate random filler bytes for the starting mix-header
   packet

The key generation function takes a key-type (_rho_=`0x72686F`, _mu_=`0x6d75`, 
_um_=`0x756d`, or _pad_=`0x706164`) and a 32-byte secret as inputs and returns
a 32-byte key.

Keys are generated by computing an HMAC (with `SHA256` as hashing algorithm)
using the appropriate key-type (i.e. _rho_, _mu_, _um_, or _pad_) as HMAC-key
and the 32-byte shared secret as the message. The resulting HMAC is then
returned as the key.

Notice that the key-type does not include a C-style `0x00`-termination-byte,
e.g. the length of the _rho_ key-type is 3 bytes, not 4.

# Pseudo Random Byte Stream

The pseudo-random byte stream is used to obfuscate the packet at each hop of the
path, so that each hop may only recover the address and HMAC of the next hop.
The pseudo-random byte stream is generated by encrypting (using `ChaCha20`) a
`0x00`-byte stream, of the required length, which is initialized with a key
derived from the shared secret and a 96-bit zero-nonce (`0x000000000000000000000000`).

The use of a fixed nonce is safe, since the keys are never reused.

# Packet Structure

The packet consists of four sections:

 - a `version` byte
 - a 33-byte compressed `secp256k1` `public_key`, used during the shared secret
   generation
 - a 1300-byte `hop_payloads` consisting of multiple, variable length,
   `hop_payload` payloads or up to 20 fixed sized legacy `hop_data` payloads.
 - a 32-byte `hmac`, used to verify the packet's integrity

The network format of the packet consists of the individual sections
serialized into one contiguous byte-stream and then transferred to the packet
recipient. Due to the fixed size of the packet, it need not be prefixed by its
length when transferred over a connection.

The overall structure of the packet is as follows:

1. type: `onion_packet`
2. data:
   * [`byte`:`version`]
   * [`point`:`public_key`]
   * [`1300*byte`:`hop_payloads`]
   * [`32*byte`:`hmac`]

For this specification (_version 0_), `version` has a constant value of `0x00`.

The `hop_payloads` field is a structure that holds obfuscated routing information, and associated HMAC.
It is 1300 bytes long and has the following structure:

1. type: `hop_payloads`
2. data:
   * [`bigsize`:`length`]
   * [`hop_payload_length`:`hop_payload`]
   * [`32*byte`:`hmac`]
   * ...
   * `filler`

Where, the `length`, `hop_payload` (with contents dependent on `length`), and `hmac` are repeated for each hop;
and where, `filler` consists of obfuscated, deterministically-generated padding, as detailed in [Filler Generation](#filler-generation).
Additionally, `hop_payloads` is incrementally obfuscated at each hop.

Using the `hop_payload` field, the origin node is able to specify the path and structure of the HTLCs forwarded at each hop.
As the `hop_payload` is protected under the packet-wide HMAC, the information it contains is fully authenticated with each pair-wise relationship between the HTLC sender (origin node) and each hop in the path.

Using this end-to-end authentication, each hop is able to cross-check the HTLC
parameters with the `hop_payload`'s specified values and to ensure that the
sending peer hasn't forwarded an ill-crafted HTLC.

The `length` field determines both the length and the format of the `hop_payload` field; the following formats are defined:

 - Legacy `hop_data` format, identified by a single `0x00` byte for length. In this case the `hop_payload_length` is defined to be 32 bytes.
 - `tlv_payload` format, identified by any length over `1`. In this case the `hop_payload_length` is equal to the numeric value of `length`.
 - A single `0x01` byte for length is reserved for future use to signal a different payload format. This is safe since no TLV value can ever be shorter than 2 bytes. In this case the `hop_payload_length` MUST be defined in the future specification making use of this `length`.

## Legacy `hop_data` payload format

The `hop_data` format is identified by a single `0x00`-byte length, for backward compatibility.
Its payload is defined as:

1. type: `hop_data` (for `realm` 0)
2. data:
   * [`short_channel_id`:`short_channel_id`]
   * [`u64`:`amt_to_forward`]
   * [`u32`:`outgoing_cltv_value`]
   * [`12*byte`:`padding`]

Field descriptions:

   * `short_channel_id`: The ID of the outgoing channel used to route the 
      message; the receiving peer should operate the other end of this channel.

   * `amt_to_forward`: The amount, in millisatoshis, to forward to the next
     receiving peer specified within the routing information.

     For non-final nodes, this value amount MUST include the origin node's computed _fee_ for the
     receiving peer. When processing an incoming Sphinx packet and the HTLC
     message that it is encapsulated within, if the following inequality doesn't hold,
     then the HTLC should be rejected as it would indicate that a prior hop has
     deviated from the specified parameters:

          incoming_htlc_amt - fee >= amt_to_forward

     Where `fee` is calculated according to the receiving peer's advertised fee
     schema (as described in [BOLT #7](07-routing-gossip.md#htlc-fees)).

     For the final node, this value MUST be exactly equal to the incoming htlc
     amount, otherwise the HTLC should be rejected.

   * `outgoing_cltv_value`: The CLTV value that the _outgoing_ HTLC carrying
     the packet should have.

          cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value

     Inclusion of this field allows a hop to both authenticate the information
     specified by the origin node, and the parameters of the HTLC forwarded,
     and ensure the origin node is using the current `cltv_expiry_delta` value.
     If there is no next hop, `cltv_expiry_delta` is 0.
     If the values don't correspond, then the HTLC should be failed and rejected, as
     this indicates that either a forwarding node has tampered with the intended HTLC
     values or that the origin node has an obsolete `cltv_expiry_delta` value.
     The hop MUST be consistent in responding to an unexpected
     `outgoing_cltv_value`, whether it is the final node or not, to avoid
     leaking its position in the route.

   * `padding`: This field is for future use and also for ensuring that future non-0-`realm`
     `hop_data`s won't change the overall `hop_payloads` size.

When forwarding HTLCs, nodes MUST construct the outgoing HTLC as specified
within `hop_data` above; otherwise, deviation from the specified HTLC
parameters may lead to extraneous routing failure.

### `tlv_payload` format

This is a more flexible format, which avoids the redundant `short_channel_id` field for the final node. 
It is formatted according to the Type-Length-Value format defined in [BOLT #1](01-messaging.md#type-length-value-format).

1. `tlv_stream`: `tlv_payload`
2. types:
    1. type: 2 (`amt_to_forward`)
    2. data:
        * [`tu64`:`amt_to_forward`]
    1. type: 4 (`outgoing_cltv_value`)
    2. data:
        * [`tu32`:`outgoing_cltv_value`]
    1. type: 6 (`short_channel_id`)
    2. data:
        * [`short_channel_id`:`short_channel_id`]
    1. type: 8 (`payment_data`)
    2. data:
        * [`32*byte`:`payment_secret`]
        * [`tu64`:`total_msat`]

### Requirements

The writer:
  - Unless `node_announcement`, `init` message or the [BOLT #11](11-payment-encoding.md#tagged-fields) offers feature `var_onion_optin`:
    - MUST use the legacy payload format instead.
  - For every node:
    - MUST include `amt_to_forward` and `outgoing_cltv_value`.
  - For every non-final node:
    - MUST include `short_channel_id`
    - MUST NOT include `payment_data`
  - For the final node:
    - MUST NOT include `short_channel_id`
    - if the recipient provided `payment_secret`:
      - MUST include `payment_data`
      - MUST set `payment_secret` to the one provided
      - MUST set `total_msat` to the total amount it will send

The reader:
  - MUST return an error if `amt_to_forward` or `outgoing_cltv_value` are not present.
  - if it is the final node:
    - MUST treat `total_msat` as if it were equal to `amt_to_forward` if it
      is not present.

The requirements for the contents of these fields are specified [above](#legacy-hop_data-payload-format)
and [below](#basic-multi-part-payments).

### Basic Multi-Part Payments

An HTLC may be part of a larger "multi-part" payment: such
"base" atomic multipath payments will use the same `payment_hash` for
all paths.

Note that `amt_to_forward` is the amount for this HTLC only: a
`total_msat` field containing a greater value is a promise by the
ultimate sender that the rest of the payment will follow in succeeding
HTLCs; we call these outstanding HTLCs which have the same preimage,
an "HTLC set".

#### Requirements

The writer:
  - if the invoice offers the `basic_mpp` feature:
    - MAY send more than one HTLC to pay the invoice.
    - MUST use the same `payment_hash` on all HTLCs in the set.
    - SHOULD send all payments at approximately the same time.
    - SHOULD try to use diverse paths to the recipient for each HTLC.
    - SHOULD retry and/or re-divide HTLCs which fail.
    - if the invoice specifies an `amount`:
       - MUST set `total_msat` to at least that `amount`, and less
         than or equal to twice `amount`.
    - otherwise:
      - MUST set `total_msat` to the amount it wishes to pay.
    - MUST ensure that the total `amount_msat` of the HTLC set which arrives at the payee
      is equal to `total_msat`.
    - MUST NOT send another HTLC if the total `amount_msat` of the HTLC set is already greater or equal to `total_msat`.
    - MUST include `payment_secret`.
  - otherwise:
    - MUST set `total_msat` equal to `amt_to_forward`.

The final node:
  - MUST fail the HTLC if dictated by Requirements under [Failure Messages](#failure-messages)
    - Note: "amount paid" specified there is the `total_msat` field.
  - if it does not support `basic_mpp`:
    - MUST fail the HTLC if `total_msat` is not exactly equal to `amt_to_forward`.
  - otherwise, if it supports `basic_mpp`:
    - MUST add it to the HTLC set corresponding to that `payment_hash`.
    - SHOULD fail the entire HTLC set if `total_msat` is not the same for
      all HTLCs in the set.
    - if the total `amount_msat` of this HTLC set equals `total_msat`:
      - SHOULD fulfill all HTLCs in the HTLC set
    - otherwise, if the total `amount_msat` of this HTLC set is less than
      `total_msat`:
      - MUST NOT fulfill any HTLCs in the HTLC set
      - MUST fail all HTLCs in the HTLC set after some reasonable timeout.
        - SHOULD wait for at least 60 seconds after the initial HTLC.
        - SHOULD use `mpp_timeout` for the failure message.
      - MUST require `payment_secret` for all HTLCs in the set.
    - if it fulfills any HTLCs in the HTLC set:
       - MUST fulfill the entire HTLC set.

#### Rationale

If `basic_mpp` is present it causes a delay to allow other partial
payments to combine.  The total amount must be sufficient for the
desired payment, just as it must be for single payments.  But this must
be reasonably bounded to avoid a denial-of-service.

Because invoices do not necessarily specify an amount, and because
payers can add noise to the final amount, the total amount must be
sent explicitly.  The requirements allow exceeding this slightly, as
it simplifies adding noise to the amount when splitting, as well as
scenarios in which the senders are genuinely independent (friends
splitting a bill, for example).

The restriction on sending an HTLC once the set is over the agreed total prevents the preimage being released before all
the partial payments have arrived: that would allow any intermediate
node to immediately claim any outstanding partial payments.

An implementation may choose not to fulfill an HTLC set which
otherwise meets the amount criterion (eg. some other failure, or
invoice timeout), however if it were to fulfill only some of them,
intermediary nodes could simply claim the remaining ones.

# Accepting and Forwarding a Payment

Once a node has decoded the payload it either accepts the payment locally, or forwards it to the peer indicated as the next hop in the payload.

## Non-strict Forwarding

A node MAY forward an HTLC along an outgoing channel other than the one
specified by `short_channel_id`, so long as the receiver has the same node
public key intended by `short_channel_id`. Thus, if `short_channel_id` connects
nodes A and B, the HTLC can be forwarded across any channel connecting A and B.
Failure to adhere will result in the receiver being unable to decrypt the next
hop in the onion packet.

### Rationale

In the event that two peers have multiple channels, the downstream node will be
able to decrypt the next hop payload regardless of which channel the packet is
sent across.

Nodes implementing non-strict forwarding are able to make real-time assessments
of channel bandwidths with a particular peer, and use the channel that is
locally-optimal. 

For example, if the channel specified by `short_channel_id` connecting A and B
does not have enough bandwidth at forwarding time, then A is able use a
different channel that does. This can reduce payment latency by preventing the
HTLC from failing due to bandwidth constraints across `short_channel_id`, only
to have the sender attempt the same route differing only in the channel between
A and B.

Non-strict forwarding allows nodes to make use of private channels connecting
them to the receiving node, even if the channel is not known in the public
channel graph.

### Recommendation

Implementations using non-strict forwarding should consider applying the same
fee schedule to all channels with the same peer, as senders are likely to select
the channel which results in the lowest overall cost. Having distinct policies
may result in the forwarding node accepting fees based on the most optimal fee
schedule for the sender, even though they are providing aggregate bandwidth
across all channels with the same peer.

Alternatively, implementations may choose to apply non-strict forwarding only to
like-policy channels to ensure their expected fee revenue does not deviate by
using an alternate channel.

## Payload for the Last Node

When building the route, the origin node MUST use a payload for
the final node with the following values:

* `payment_secret`: set to the payment secret specified by the recipient (e.g.
  `payment_secret` from a [BOLT #11](11-payment-encoding.md) payment invoice)
* `outgoing_cltv_value`: set to the final expiry specified by the recipient (e.g.
  `min_final_cltv_expiry` from a [BOLT #11](11-payment-encoding.md) payment invoice)
* `amt_to_forward`: set to the final amount specified by the recipient (e.g. `amount`
  from a [BOLT #11](11-payment-encoding.md) payment invoice)

This allows the final node to check these values and return errors if needed,
but it also eliminates the possibility of probing attacks by the second-to-last
node. Such attacks could, otherwise, attempt to discover if the receiving peer is the
last one by re-sending HTLCs with different amounts/expiries.
The final node will extract its onion payload from the HTLC it has received and
compare its values against those of the HTLC. See the
[Returning Errors](#returning-errors) section below for more details.

If not for the above, since it need not forward payments, the final node could
simply discard its payload.

# Shared Secret

The origin node establishes a shared secret with each hop along the route using
Elliptic-curve Diffie-Hellman between the sender's ephemeral key at that hop and
the hop's node ID key. The resulting curve point is serialized to the
compressed format and hashed using `SHA256`. The hash output is used
as the 32-byte shared secret.

Elliptic-curve Diffie-Hellman (ECDH) is an operation on an EC private key and
an EC public key that outputs a curve point. For this protocol, the ECDH
variant implemented in `libsecp256k1` is used, which is defined over the
`secp256k1` elliptic curve. During packet construction, the sender uses the
ephemeral private key and the hop's public key as inputs to ECDH, whereas
during packet forwarding, the hop uses the ephemeral public key and its own
node ID private key. Because of the properties of ECDH, they will both derive
the same value.

# Blinding Ephemeral Keys

In order to ensure multiple hops along the route cannot be linked by the
ephemeral public keys they see, the key is blinded at each hop. The blinding is
done in a deterministic way that allows the sender to compute the
corresponding blinded private keys during packet construction.

The blinding of an EC public key is a single scalar multiplication of
the EC point representing the public key with a 32-byte blinding factor. Due to
the commutative property of scalar multiplication, the blinded private key is
the multiplicative product of the input's corresponding private key with the
same blinding factor.

The blinding factor itself is computed as a function of the ephemeral public key
and the 32-byte shared secret. Concretely, it is the `SHA256` hash value of the
concatenation of the public key serialized in its compressed format and the
shared secret.

# Packet Construction

In the following example, it's assumed that a _sending node_ (origin node),
`n_0`, wants to route a packet to a _receiving node_ (final node), `n_r`.
First, the sender computes a route `{n_0, n_1, ..., n_{r-1}, n_r}`, where `n_0`
is the sender itself and `n_r` is the final recipient. All nodes `n_i` and
`n_{i+1}` MUST be peers in the overlay network route. The sender then gathers the
public keys for `n_1` to `n_r` and generates a random 32-byte `sessionkey`.
Optionally, the sender may pass in _associated data_, i.e. data that the
packet commits to but that is not included in the packet itself. Associated
data will be included in the HMACs and must match the associated data provided
during integrity verification at each hop.

To construct the onion, the sender initializes the ephemeral private key for the
first hop `ek_1` to the `sessionkey` and derives from it the corresponding
ephemeral public key `epk_1` by multiplying with the `secp256k1` base point. For
each of the `k` hops along the route, the sender then iteratively computes the
shared secret `ss_k` and ephemeral key for the next hop `ek_{k+1}` as follows:

 - The sender executes ECDH with the hop's public key and the ephemeral private
 key to obtain a curve point, which is hashed using `SHA256` to produce the
 shared secret `ss_k`.
 - The blinding factor is the `SHA256` hash of the concatenation between the
 ephemeral public key `epk_k` and the shared secret `ss_k`.
 - The ephemeral private key for the next hop `ek_{k+1}` is computed by
 multiplying the current ephemeral private key `ek_k` by the blinding factor.
 - The ephemeral public key for the next hop `epk_{k+1}` is derived from the
 ephemeral private key `ek_{k+1}` by multiplying with the base point.

Once the sender has all the required information above, it can construct the
packet. Constructing a packet routed over `r` hops requires `r` 32-byte
ephemeral public keys, `r` 32-byte shared secrets, `r` 32-byte blinding factors,
and `r` variable length `hop_payload` payloads.
The construction returns a single 1366-byte packet along with the first receiving peer's address.

The packet construction is performed in the reverse order of the route, i.e.
the last hop's operations are applied first.

The packet is initialized with 1300 _random_ bytes derived from a CSPRNG
(ChaCha20). The _pad_ key referenced above is used to extract additional random
bytes from a ChaCha20 stream, using it as a CSPRNG for this purpose.  Once the
`paddingKey` has been obtained, ChaCha20 is used with an all zero nonce, to
generate 1300 random bytes. Those random bytes are then used as the starting
state of the mix-header to be created.

A filler is generated (see [Filler Generation](#filler-generation)) using the
shared secret.

For each hop in the route, in reverse order, the sender applies the
following operations:

 - The _rho_-key and _mu_-key are generated using the hop's shared secret.
 - `shift_size` is defined as the length of the `hop_payload` plus the bigsize encoding of the length and the length of that HMAC. Thus if the payload length is `l` then the `shift_size` is `1 + l + 32` for `l < 253`, otherwise `3 + l + 32` due to the bigsize encoding of `l`.
 - The `hop_payload` field is right-shifted by `shift_size` bytes, discarding the last `shift_size`
 bytes that exceed its 1300-byte size.
 - The bigsize-serialized length, serialized `hop_payload` and `hmac` are copied into the following `shift_size` bytes.
 - The _rho_-key is used to generate 1300 bytes of pseudo-random byte stream
 which is then applied, with `XOR`, to the `hop_payloads` field.
 - If this is the last hop, i.e. the first iteration, then the tail of the
 `hop_payloads` field is overwritten with the routing information `filler`.
 - The next HMAC is computed (with the _mu_-key as HMAC-key) over the
 concatenated `hop_payloads` and associated data.

The resulting final HMAC value is the HMAC that will be used by the first
receiving peer in the route.

The packet generation returns a serialized packet that contains the `version`
byte, the ephemeral pubkey for the first hop, the HMAC for the first hop, and
the obfuscated `hop_payloads`.

The following Go code is an example implementation of the packet construction:

```Go
func NewOnionPacket(paymentPath []*btcec.PublicKey, sessionKey *btcec.PrivateKey,
	hopsData []HopData, assocData []byte) (*OnionPacket, error) {

	numHops := len(paymentPath)
	hopSharedSecrets := make([][sha256.Size]byte, numHops)

	// Initialize ephemeral key for the first hop to the session key.
	var ephemeralKey big.Int
	ephemeralKey.Set(sessionKey.D)

	for i := 0; i < numHops; i++ {
		// Perform ECDH and hash the result.
		ecdhResult := scalarMult(paymentPath[i], ephemeralKey)
		hopSharedSecrets[i] = sha256.Sum256(ecdhResult.SerializeCompressed())

		// Derive ephemeral public key from private key.
		ephemeralPrivKey := btcec.PrivKeyFromBytes(btcec.S256(), ephemeralKey.Bytes())
		ephemeralPubKey := ephemeralPrivKey.PubKey()

		// Compute blinding factor.
		sha := sha256.New()
		sha.Write(ephemeralPubKey.SerializeCompressed())
		sha.Write(hopSharedSecrets[i])

		var blindingFactor big.Int
		blindingFactor.SetBytes(sha.Sum(nil))

		// Blind ephemeral key for next hop.
		ephemeralKey.Mul(&ephemeralKey, &blindingFactor)
		ephemeralKey.Mod(&ephemeralKey, btcec.S256().Params().N)
	}

	// Generate the padding, called "filler strings" in the paper.
	filler := generateHeaderPadding("rho", numHops, hopDataSize, hopSharedSecrets)

	// Allocate and initialize fields to zero-filled slices
	var mixHeader [routingInfoSize]byte
	var nextHmac [hmacSize]byte
        
        // Our starting packet needs to be filled out with random bytes, we
        // generate some determinstically using the session private key.
        paddingKey := generateKey("pad", sessionKey.Serialize()
        paddingBytes := generateCipherStream(paddingKey, routingInfoSize)
        copy(mixHeader[:], paddingBytes)

	// Compute the routing information for each hop along with a
	// MAC of the routing information using the shared key for that hop.
	for i := numHops - 1; i >= 0; i-- {
		rhoKey := generateKey("rho", hopSharedSecrets[i])
		muKey := generateKey("mu", hopSharedSecrets[i])

		hopsData[i].HMAC = nextHmac

		// Shift and obfuscate routing information
		streamBytes := generateCipherStream(rhoKey, numStreamBytes)

		rightShift(mixHeader[:], hopDataSize)
		buf := &bytes.Buffer{}
		hopsData[i].Encode(buf)
		copy(mixHeader[:], buf.Bytes())
		xor(mixHeader[:], mixHeader[:], streamBytes[:routingInfoSize])

		// These need to be overwritten, so every node generates a correct padding
		if i == numHops-1 {
			copy(mixHeader[len(mixHeader)-len(filler):], filler)
		}

		packet := append(mixHeader[:], assocData...)
		nextHmac = calcMac(muKey, packet)
	}

	packet := &OnionPacket{
		Version:      0x00,
		EphemeralKey: sessionKey.PubKey(),
		RoutingInfo:  mixHeader,
		HeaderMAC:    nextHmac,
	}
	return packet, nil
}
```

# Packet Forwarding

This specification is limited to `version` `0` packets; the structure
of future versions may change.

Upon receiving a packet, a processing node compares the version byte of the
packet with its own supported versions and aborts the connection if the packet
specifies a version number that it doesn't support.
For packets with supported version numbers, the processing node first parses the
packet into its individual fields.

Next, the processing node computes the shared secret using the private key
corresponding to its own public key and the ephemeral key from the packet, as
described in [Shared Secret](#shared-secret).

The above requirements prevent any hop along the route from retrying a payment
multiple times, in an attempt to track a payment's progress via traffic
analysis. Note that disabling such probing could be accomplished using a log of
previous shared secrets or HMACs, which could be forgotten once the HTLC would
not be accepted anyway (i.e. after `outgoing_cltv_value` has passed). Such a log
may use a probabilistic data structure, but it MUST rate-limit commitments as
necessary, in order to constrain the worst-case storage requirements or false
positives of this log.

Next, the processing node uses the shared secret to compute a _mu_-key, which it
in turn uses to compute the HMAC of the `hop_payloads`. The resulting HMAC is then
compared against the packet's HMAC.

Comparison of the computed HMAC and the packet's HMAC MUST be
time-constant to avoid information leaks.

At this point, the processing node can generate a _rho_-key and a _gamma_-key.

The routing information is then deobfuscated, and the information about the
next hop is extracted.
To do so, the processing node copies the `hop_payloads` field, appends 1300 `0x00`-bytes,
generates `2*1300` pseudo-random bytes (using the _rho_-key), and applies the result, using `XOR`, to the copy of the `hop_payloads`.
The first few bytes correspond to the bigsize-encoded length `l` of the `hop_payload`, followed by `l` bytes of the resulting routing information become the `hop_payload`, and the 32 byte HMAC.
The next 1300 bytes are the `hop_payloads` for the outgoing packet.

A special `hmac` value of 32 `0x00`-bytes indicates that the currently processing hop is the intended recipient and that the packet should not be forwarded.

If the HMAC does not indicate route termination, and if the next hop is a peer of the
processing node; then the new packet is assembled. Packet assembly is accomplished
by blinding the ephemeral key with the processing node's public key, along with the
shared secret, and by serializing the `hop_payloads`.
The resulting packet is then forwarded to the addressed peer.

## Requirements

The processing node:
  - if the ephemeral public key is NOT on the `secp256k1` curve:
    - MUST abort processing the packet.
    - MUST report a route failure to the origin node.
  - if the packet has previously been forwarded or locally redeemed, i.e. the
  packet contains duplicate routing information to a previously received packet:
    - if preimage is known:
      - MAY immediately redeem the HTLC using the preimage.
    - otherwise:
      - MUST abort processing and report a route failure.
  - if the computed HMAC and the packet's HMAC differ:
    - MUST abort processing.
    - MUST report a route failure.
  - if the `realm` is unknown:
    - MUST drop the packet.
    - MUST signal a route failure.
  - MUST address the packet to another peer that is its direct neighbor.
  - if the processing node does not have a peer with the matching address:
    - MUST drop the packet.
    - MUST signal a route failure.


# Filler Generation

Upon receiving a packet, the processing node extracts the information destined
for it from the route information and the per-hop payload.
The extraction is done by deobfuscating and left-shifting the field.
This would make the field shorter at each hop, allowing an attacker to deduce the
route length. For this reason, the field is pre-padded before forwarding.
Since the padding is part of the HMAC, the origin node will have to pre-generate an
identical padding (to that which each hop will generate) in order to compute the
HMACs correctly for each hop.
The filler is also used to pad the field-length, in the case that the selected
route is shorter than 1300 bytes.

Before deobfuscating the `hop_payloads`, the processing node pads it with 1300
`0x00`-bytes, such that the total length is `2*1300`.
It then generates the pseudo-random byte stream, of matching length, and applies
it with `XOR` to the `hop_payloads`.
This deobfuscates the information destined for it, while simultaneously
obfuscating the added `0x00`-bytes at the end.

In order to compute the correct HMAC, the origin node has to pre-generate the
`hop_payloads` for each hop, including the incrementally obfuscated padding added
by each hop. This incrementally obfuscated padding is referred to as the
`filler`.

The following example code shows how the filler is generated in Go:

```Go
func generateFiller(key string, numHops int, hopSize int, sharedSecrets [][sharedSecretSize]byte) []byte {
	fillerSize := uint((numMaxHops + 1) * hopSize)
	filler := make([]byte, fillerSize)

	// The last hop does not obfuscate, it's not forwarding anymore.
	for i := 0; i < numHops-1; i++ {

		// Left-shift the field
		copy(filler[:], filler[hopSize:])

		// Zero-fill the last hop
		copy(filler[len(filler)-hopSize:], bytes.Repeat([]byte{0x00}, hopSize))

		// Generate pseudo-random byte stream
		streamKey := generateKey(key, sharedSecrets[i])
		streamBytes := generateCipherStream(streamKey, fillerSize)

		// Obfuscate
		xor(filler, filler, streamBytes)
	}

	// Cut filler down to the correct length (numHops+1)*hopSize
	// bytes will be prepended by the packet generation.
	return filler[(numMaxHops-numHops+2)*hopSize:]
}
```

Note that this example implementation is for demonstration purposes only; the
`filler` can be generated much more efficiently.
The last hop need not obfuscate the `filler`, since it won't forward the packet
any further and thus need not extract an HMAC either.

# Returning Errors

The onion routing protocol includes a simple mechanism for returning encrypted
error messages to the origin node.
The returned error messages may be failures reported by any hop, including the
final node.
The format of the forward packet is not usable for the return path, since no hop
besides the origin has access to the information required for its generation.
Note that these error messages are not reliable, as they are not placed on-chain
due to the possibility of hop failure.

Intermediate hops store the shared secret from the forward path and reuse it to
obfuscate any corresponding return packet during each hop.
In addition, each node locally stores data regarding its own sending peer in the
route, so it knows where to return-forward any eventual return packets.
The node generating the error message (_erring node_) builds a return packet
consisting of the following fields:

1. data:
   * [`32*byte`:`hmac`]
   * [`u16`:`failure_len`]
   * [`failure_len*byte`:`failuremsg`]
   * [`u16`:`pad_len`]
   * [`pad_len*byte`:`pad`]

Where `hmac` is an HMAC authenticating the remainder of the packet, with a key
generated using the above process, with key type `um`, `failuremsg` as defined
below, and `pad` as the extra bytes used to conceal length.

The erring node then generates a new key, using the key type `ammag`.
This key is then used to generate a pseudo-random stream, which is in turn
applied to the packet using `XOR`.

The obfuscation step is repeated by every hop along the return path.
Upon receiving a return packet, each hop generates its `ammag`, generates the
pseudo-random byte stream, and applies the result to the return packet before
return-forwarding it.

The origin node is able to detect that it's the intended final recipient of the
return message, because of course, it was the originator of the corresponding
forward packet.
When an origin node receives an error message matching a transfer it initiated
(i.e. it cannot return-forward the error any further) it generates the `ammag`
and `um` keys for each hop in the route.
It then iteratively decrypts the error message, using each hop's `ammag`
key, and computes the HMAC, using each hop's `um` key.
The origin node can detect the sender of the error message by matching the
`hmac` field with the computed HMAC.

The association between the forward and return packets is handled outside of
this onion routing protocol, e.g. via association with an HTLC in a payment
channel.

### Requirements

The _erring node_:
  - SHOULD set `pad` such that the `failure_len` plus `pad_len` is equal to 256.
    - Note: this value is 118 bytes longer than the longest currently-defined
    message.

The _origin node_:
  - once the return message has been decrypted:
    - SHOULD store a copy of the message.
    - SHOULD continue decrypting, until the loop has been repeated 20 times.
    - SHOULD use constant `ammag` and `um` keys to obfuscate the route length.

## Failure Messages

The failure message encapsulated in `failuremsg` has an identical format as
a normal message: a 2-byte type `failure_code` followed by data applicable
to that type. Below is a list of the currently supported `failure_code`
values, followed by their use case requirements.

Notice that the `failure_code`s are not of the same type as other message types,
defined in other BOLTs, as they are not sent directly on the transport layer
but are instead wrapped inside return packets.
The numeric values for the `failure_code` may therefore reuse values, that are
also assigned to other message types, without any danger of causing collisions.

The top byte of `failure_code` can be read as a set of flags:
* 0x8000 (BADONION): unparsable onion encrypted by sending peer
* 0x4000 (PERM): permanent failure (otherwise transient)
* 0x2000 (NODE): node failure (otherwise channel)
* 0x1000 (UPDATE): new channel update enclosed

Please note that the `channel_update` field is mandatory in messages whose
`failure_code` includes the `UPDATE` flag.

The following `failure_code`s are defined:

1. type: PERM|1 (`invalid_realm`)

The `realm` byte was not understood by the processing node.

1. type: NODE|2 (`temporary_node_failure`)

General temporary failure of the processing node.

1. type: PERM|NODE|2 (`permanent_node_failure`)

General permanent failure of the processing node.

1. type: PERM|NODE|3 (`required_node_feature_missing`)

The processing node has a required feature which was not in this onion.

1. type: BADONION|PERM|4 (`invalid_onion_version`)
2. data:
   * [`sha256`:`sha256_of_onion`]

The `version` byte was not understood by the processing node.

1. type: BADONION|PERM|5 (`invalid_onion_hmac`)
2. data:
   * [`sha256`:`sha256_of_onion`]

The HMAC of the onion was incorrect when it reached the processing node.

1. type: BADONION|PERM|6 (`invalid_onion_key`)
2. data:
   * [`sha256`:`sha256_of_onion`]

The ephemeral key was unparsable by the processing node.

1. type: UPDATE|7 (`temporary_channel_failure`)
2. data:
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The channel from the processing node was unable to handle this HTLC,
but may be able to handle it, or others, later.

1. type: PERM|8 (`permanent_channel_failure`)

The channel from the processing node is unable to handle any HTLCs.

1. type: PERM|9 (`required_channel_feature_missing`)

The channel from the processing node requires features not present in
the onion.

1. type: PERM|10 (`unknown_next_peer`)

The onion specified a `short_channel_id` which doesn't match any
leading from the processing node.

1. type: UPDATE|11 (`amount_below_minimum`)
2. data:
   * [`u64`:`htlc_msat`]
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The HTLC amount was below the `htlc_minimum_msat` of the channel from
the processing node.

1. type: UPDATE|12 (`fee_insufficient`)
2. data:
   * [`u64`:`htlc_msat`]
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The fee amount was below that required by the channel from the
processing node.

1. type: UPDATE|13 (`incorrect_cltv_expiry`)
2. data:
   * [`u32`:`cltv_expiry`]
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The `cltv_expiry` does not comply with the `cltv_expiry_delta` required by
the channel from the processing node: it does not satisfy the following
requirement:

        cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value

1. type: UPDATE|14 (`expiry_too_soon`)
2. data:
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The CLTV expiry is too close to the current block height for safe
handling by the processing node.

1. type: PERM|15 (`incorrect_or_unknown_payment_details`)
2. data:
   * [`u64`:`htlc_msat`]
   * [`u32`:`height`]

The `payment_hash` is unknown to the final node, the `payment_secret` doesn't
match the `payment_hash`, the amount for that `payment_hash` is incorrect or
the CLTV expiry of the htlc is too close to the current block height for safe
handling.

The `htlc_msat` parameter is superfluous, but left in for backwards
compatibility. The value of `htlc_msat` always matches the amount specified in
the final hop onion payload. It therefore does not have any informative value to
the sender. A penultimate hop sending a different amount or expiry for the htlc
is handled through `final_incorrect_cltv_expiry` and
`final_incorrect_htlc_amount`.

The `height` parameter is set by the final node to the best known block height
at the time of receiving the htlc. This can be used by the sender to distinguish
between sending a payment with the wrong final CLTV expiry and an intermediate
hop delaying the payment so that the receiver's invoice CLTV delta requirement
is no longer met.

Note: Originally PERM|16 (`incorrect_payment_amount`) and 17
(`final_expiry_too_soon`) were used to differentiate incorrect htlc parameters
from unknown payment hash. Sadly, sending this response allows for probing
attacks whereby a node which receives an HTLC for forwarding can check guesses
as to its final destination by sending payments with the same hash but much
lower values or expiry heights to potential destinations and check the response.
Care must be taken by implementations to differentiate the previously
non-permanent case for `final_expiry_too_soon` (17) from the other, permanent
failures now represented by `incorrect_or_unknown_payment_details` (PERM|15).

1. type: 18 (`final_incorrect_cltv_expiry`)
2. data:
   * [`u32`:`cltv_expiry`]

The CLTV expiry in the HTLC doesn't match the value in the onion.

1. type: 19 (`final_incorrect_htlc_amount`)
2. data:
   * [`u64`:`incoming_htlc_amt`]

The amount in the HTLC doesn't match the value in the onion.

1. type: UPDATE|20 (`channel_disabled`)
2. data:
   * [`u16`:`flags`]
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The channel from the processing node has been disabled.

1. type: 21 (`expiry_too_far`)

The CLTV expiry in the HTLC is too far in the future.

1. type: PERM|22 (`invalid_onion_payload`)
2. data:
   * [`bigsize`:`type`]
   * [`u16`:`offset`]

The decrypted onion per-hop payload was not understood by the processing node
or is incomplete. If the failure can be narrowed down to a specific tlv type in
the payload, the erring node may include that `type` and its byte `offset` in
the decrypted byte stream.

1. type: 23 (`mpp_timeout`)

The complete amount of the multi-part payment was not received within a
reasonable time.

### Requirements

An _erring node_:
  - MUST select one of the above error codes when creating an error message.
  - MUST include the appropriate data for that particular error type.
  - if there is more than one error:
    - SHOULD select the first error it encounters from the list above.

Any _erring node_ MAY:
  - if the `realm` byte is unknown:
    - return an `invalid_realm` error.
  - if the per-hop payload in the onion is invalid (e.g. it is not a valid tlv stream)
  or is missing required information (e.g. the amount was not specified):
    - return an `invalid_onion_payload` error.
  - if an otherwise unspecified transient error occurs for the entire node:
    - return a `temporary_node_failure` error.
  - if an otherwise unspecified permanent error occurs for the entire node:
    - return a `permanent_node_failure` error.
  - if a node has requirements advertised in its `node_announcement` `features`,
  which were NOT included in the onion:
    - return a `required_node_feature_missing` error.

A _forwarding node_ MAY, but a _final node_ MUST NOT:
  - if the onion `version` byte is unknown:
    - return an `invalid_onion_version` error.
  - if the onion HMAC is incorrect:
    - return an `invalid_onion_hmac` error.
  - if the ephemeral key in the onion is unparsable:
    - return an `invalid_onion_key` error.
  - if during forwarding to its receiving peer, an otherwise unspecified,
  transient error occurs in the outgoing channel (e.g. channel capacity reached,
  too many in-flight HTLCs, etc.):
    - return a `temporary_channel_failure` error.
  - if an otherwise unspecified, permanent error occurs during forwarding to its
  receiving peer (e.g. channel recently closed):
    - return a `permanent_channel_failure` error.
  - if the outgoing channel has requirements advertised in its
  `channel_announcement`'s `features`, which were NOT included in the onion:
    - return a `required_channel_feature_missing` error.
  - if the receiving peer specified by the onion is NOT known:
    - return an `unknown_next_peer` error.
  - if the HTLC amount is less than the currently specified minimum amount:
    - report the amount of the outgoing HTLC and the current channel setting for
    the outgoing channel.
    - return an `amount_below_minimum` error.
  - if the HTLC does NOT pay a sufficient fee:
    - report the amount of the incoming HTLC and the current channel setting for
    the outgoing channel.
    - return a `fee_insufficient` error.
 -  if the incoming `cltv_expiry` minus the `outgoing_cltv_value` is below the
    `cltv_expiry_delta` for the outgoing channel:
    - report the `cltv_expiry` of the outgoing HTLC and the current channel setting for the outgoing
    channel.
    - return an `incorrect_cltv_expiry` error.
  - if the `cltv_expiry` is unreasonably near the present:
    - report the current channel setting for the outgoing channel.
    - return an `expiry_too_soon` error.
  - if the `cltv_expiry` is unreasonably far in the future:
    - return an `expiry_too_far` error.
  - if the channel is disabled:
    - report the current channel setting for the outgoing channel.
    - return a `channel_disabled` error.

An _intermediate hop_ MUST NOT, but the _final node_:
  - if the payment hash has already been paid:
    - MAY treat the payment hash as unknown.
    - MAY succeed in accepting the HTLC.
  - if the `payment_secret` doesn't match the expected value for that `payment_hash`,
    or the `payment_secret` is required and is not present:
    - MUST fail the HTLC.
    - MUST return an `incorrect_or_unknown_payment_details` error.
  - if the amount paid is less than the amount expected:
    - MUST fail the HTLC.
    - MUST return an `incorrect_or_unknown_payment_details` error.
  - if the payment hash is unknown:
    - MUST fail the HTLC.
    - MUST return an `incorrect_or_unknown_payment_details` error.
  - if the amount paid is more than twice the amount expected:
    - SHOULD fail the HTLC.
    - SHOULD return an `incorrect_or_unknown_payment_details` error.
      - Note: this allows the origin node to reduce information leakage by
      altering the amount while not allowing for accidental gross overpayment.
  - if the `cltv_expiry` value is unreasonably near the present:
    - MUST fail the HTLC.
    - MUST return an `incorrect_or_unknown_payment_details` error.
  - if the `outgoing_cltv_value` does NOT correspond with the `cltv_expiry` from
  the final node's HTLC:
    - MUST return `final_incorrect_cltv_expiry` error.
  - if the `amt_to_forward` does NOT correspond with the `incoming_htlc_amt` from the
  final node's HTLC:
    - MUST return a `final_incorrect_htlc_amount` error.

## Receiving Failure Codes

### Requirements

The _origin node_:
  - MUST ignore any extra bytes in `failuremsg`.
  - if the _final node_ is returning the error:
    - if the PERM bit is set:
      - SHOULD fail the payment.
    - otherwise:
      - if the error code is understood and valid:
        - MAY retry the payment. In particular, `final_expiry_too_soon` can
        occur if the block height has changed since sending, and in this case
        `temporary_node_failure` could resolve within a few seconds.
  - otherwise, an _intermediate hop_ is returning the error:
    - if the NODE bit is set:
      - SHOULD remove all channels connected with the erring node from
      consideration.
    - if the PERM bit is NOT set:
      - SHOULD restore the channels as it receives new `channel_update`s.
    - otherwise:
      - if UPDATE is set, AND the `channel_update` is valid and more recent
      than the `channel_update` used to send the payment:
        - if `channel_update` should NOT have caused the failure:
          - MAY treat the `channel_update` as invalid.
        - otherwise:
          - SHOULD apply the `channel_update`.
        - MAY queue the `channel_update` for broadcast.
      - otherwise:
        - SHOULD eliminate the channel outgoing from the erring node from
        consideration.
        - if the PERM bit is NOT set:
          - SHOULD restore the channel as it receives new `channel_update`s.
    - SHOULD then retry routing and sending the payment.
  - MAY use the data specified in the various failure types for debugging
  purposes.

# Test Vector

## Returning Errors

The test vectors use the following parameters:

	pubkey[0] = 0x02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
	pubkey[1] = 0x0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
	pubkey[2] = 0x027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007
	pubkey[3] = 0x032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991
	pubkey[4] = 0x02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145

	nhops = 5/20
	sessionkey = 0x4141414141414141414141414141414141414141414141414141414141414141
	associated data = 0x4242424242424242424242424242424242424242424242424242424242424242

The following is an in-depth trace of an example of error message creation:

	# node 4 is returning an error
	failure_message = 2002
	# creating error message
	shared_secret = b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328
	payload = 0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	um_key = 4da7f2923edce6c2d85987d1d9fa6d88023e6c3a9c3d20f07d3b10b61a78d646
	raw_error_packet = 4c2fc8bc08510334b6833ad9c3e79cd1b52ae59dfe5c2a4b23ead50f09f7ee0b0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	# forwarding error packet
	shared_secret = b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328
	 ammag_key = 2f36bb8822e1f0d04c27b7d8bb7d7dd586e032a3218b8d414afbba6f169a4d68
	stream = e9c975b07c9a374ba64fd9be3aae955e917d34d1fa33f2e90f53bbf4394713c6a8c9b16ab5f12fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4
	error packet for node 4: a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4
	# forwarding error packet
	shared_secret = 21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d
	ammag_key = cd9ac0e09064f039fa43a31dea05f5fe5f6443d40a98be4071af4a9d704be5ad
	stream = 617ca1e4624bc3f04fece3aa5a2b615110f421ec62408d16c48ea6c1b7c33fe7084a2bd9d4652fc5068e5052bf6d0acae2176018a3d8c75f37842712913900263cff92f39f3c18aa1f4b20a93e70fc429af7b2b1967ca81a761d40582daf0eb49cef66e3d6fbca0218d3022d32e994b41c884a27c28685ef1eb14603ea80a204b2f2f474b6ad5e71c6389843e3611ebeafc62390b717ca53b3670a33c517ef28a659c251d648bf4c966a4ef187113ec9848bf110816061ca4f2f68e76ceb88bd6208376460b916fb2ddeb77a65e8f88b2e71a2cbf4ea4958041d71c17d05680c051c3676fb0dc8108e5d78fb1e2c44d79a202e9d14071d536371ad47c39a05159e8d6c41d17a1e858faaaf572623aa23a38ffc73a4114cb1ab1cd7f906c6bd4e21b29694
	error packet for node 3: c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55b4e837c83a8773c22aa081bab1616a0011585323930fa5b9fae0c85770a2279ff59ec427ad1bbff9001c0cd1497004bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2af978cbe31c67114440ac51a62081df0ed46d4a3df295da0b0fe25c0115019f03f15ec86fabb4c852f83449e812f141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15abfe8fd3a6261e52650e8807a92158d9f1463261a925e4bfba44bd20b166d532f0017185c3a6ac7957adefe45559e3072c8dc35abeba835a8cb01a71a15c736911126f27d46a36168ca5ef7dccd4e2886212602b181463e0dd30185c96348f9743a02aca8ec27c0b90dca270
	forwarding error packet
	shared_secret = 3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc
	ammag_key = 1bf08df8628d452141d56adfd1b25c1530d7921c23cecfc749ac03a9b694b0d3
	stream = 6149f48b5a7e8f3d6f5d870b7a698e204cf64452aab4484ff1dee671fe63fd4b5f1b78ee2047dfa61e3d576b149bedaf83058f85f06a3172a3223ad6c4732d96b32955da7d2feb4140e58d86fc0f2eb5d9d1878e6f8a7f65ab9212030e8e915573ebbd7f35e1a430890be7e67c3fb4bbf2def662fa625421e7b411c29ebe81ec67b77355596b05cc155755664e59c16e21410aabe53e80404a615f44ebb31b365ca77a6e91241667b26c6cad24fb2324cf64e8b9dd6e2ce65f1f098cfd1ef41ba2d4c7def0ff165a0e7c84e7597c40e3dffe97d417c144545a0e38ee33ebaae12cc0c14650e453d46bfc48c0514f354773435ee89b7b2810606eb73262c77a1d67f3633705178d79a1078c3a01b5fadc9651feb63603d19decd3a00c1f69af2dab259593
	error packet for node 2: a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1dfb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e545563cdd8f5524dae873de61d7bdfccd496af2584930d2b566b4f8d3881f8c043df92224f38cf094cfc09d92655989531524593ec6d6caec1863bdfaa79229b5020acc034cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0af5d6b07c017f7158fa94f0d206baf12dda6b68f785b773b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a45c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bdb0d347718b9aeff5b61dfff344993a275b79717cd815b6ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6eaa0375e0aaf738ac691abd3263bf937e3
	# forwarding error packet
	shared_secret = a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae
	ammag_key = 59ee5867c5c151daa31e36ee42530f429c433836286e63744f2020b980302564
	stream = 0f10c86f05968dd91188b998ee45dcddfbf89fe9a99aa6375c42ed5520a257e048456fe417c15219ce39d921555956ae2ff795177c63c819233f3bcb9b8b28e5ac6e33a3f9b87ca62dff43f4cc4a2755830a3b7e98c326b278e2bd31f4a9973ee99121c62873f5bfb2d159d3d48c5851e3b341f9f6634f51939188c3b9ff45feeb11160bb39ce3332168b8e744a92107db575ace7866e4b8f390f1edc4acd726ed106555900a0832575c3a7ad11bb1fe388ff32b99bcf2a0d0767a83cf293a220a983ad014d404bfa20022d8b369fe06f7ecc9c74751dcda0ff39d8bca74bf9956745ba4e5d299e0da8f68a9f660040beac03e795a046640cf8271307a8b64780b0588422f5a60ed7e36d60417562938b400802dac5f87f267204b6d5bcfd8a05b221ec2
	error packet for node 1: aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bbcc45abc31e59b26881b7dfadbb56ec8dae8857add94e6702fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4932acd62727b75348a648a1128744657ca6a4e713b9b646c3ca66cac02cdab44dd3439890ef3aaf61708714f7375349b8da541b2548d452d84de7084bb95b3ac2345201d624d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919ea305a8949de95e935eed0319cf3cf19ebea61d76ba92532497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f29339dfee3331995b21615337ae060233d39befea925cc262873e0530408e6990f1cbd233a150ef7b004ff6166c70c68d9f8c853c1abca640b8660db2921
	# forwarding error packet
	shared_secret = 53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66
	ammag_key = 3761ba4d3e726d8abb16cba5950ee976b84937b61b7ad09e741724d7dee12eb5
	stream = 3699fd352a948a05f604763c0bca2968d5eaca2b0118602e52e59121f050936c8dd90c24df7dc8cf8f1665e39a6c75e9e2c0900ea245c9ed3b0008148e0ae18bbfaea0c711d67eade980c6f5452e91a06b070bbde68b5494a92575c114660fb53cf04bf686e67ffa4a0f5ae41a59a39a8515cb686db553d25e71e7a97cc2febcac55df2711b6209c502b2f8827b13d3ad2f491c45a0cafe7b4d8d8810e805dee25d676ce92e0619b9c206f922132d806138713a8f69589c18c3fdc5acee41c1234b17ecab96b8c56a46787bba2c062468a13919afc18513835b472a79b2c35f9a91f38eb3b9e998b1000cc4a0dbd62ac1a5cc8102e373526d7e8f3c3a1b4bfb2f8a3947fe350cb89f73aa1bb054edfa9895c0fc971c2b5056dc8665902b51fced6dff80c
	error packet for node 0: 9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d

# References

[sphinx]: http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf
[RFC2104]: https://tools.ietf.org/html/rfc2104
[fips198]: http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
[sec2]: http://www.secg.org/sec2-v2.pdf
[rfc8439]: https://tools.ietf.org/html/rfc8439

# Authors

[ FIXME: ]

![Creative Commons License](https://i.creativecommons.org/l/by/4.0/88x31.png "License CC-BY")
<br>
This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).
"""
