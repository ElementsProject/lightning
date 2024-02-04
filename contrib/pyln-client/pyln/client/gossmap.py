#! /usr/bin/python3

from pyln.spec.bolt7 import (channel_announcement, channel_update,
                             node_announcement)
from pyln.proto import ShortChannelId, PublicKey
from typing import Any, Dict, List, Set, Optional, Union

import io
import base64
import socket
import struct
import time

# These duplicate constants in lightning/common/gossip_store.h
GOSSIP_STORE_MAJOR_VERSION = (0 << 5)
GOSSIP_STORE_MAJOR_VERSION_MASK = 0xE0
GOSSIP_STORE_LEN_DELETED_BIT = 0x8000
GOSSIP_STORE_LEN_PUSH_BIT = 0x4000

# These duplicate constants in lightning/gossipd/gossip_store_wiregen.h
WIRE_GOSSIP_STORE_PRIVATE_CHANNEL = 4104
WIRE_GOSSIP_STORE_PRIVATE_UPDATE = 4102
WIRE_GOSSIP_STORE_DELETE_CHAN = 4103
WIRE_GOSSIP_STORE_ENDED = 4105
WIRE_GOSSIP_STORE_CHANNEL_AMOUNT = 4101


class LnFeatureBits(object):
    """ feature flags taken from bolts.git/09-features.md

 Flags are numbered from the least-significant bit, at bit 0 (i.e. 0x1,
 an _even_ bit). They are generally assigned in pairs so that features
 can be introduced as optional (_odd_ bits) and later upgraded to be compulsory
 (_even_ bits), which will be refused by outdated nodes:

 CONTEXT:
 * `I`: presented in the `init` message.
 * `N`: presented in the `node_announcement` messages
 * `C`: presented in the `channel_announcement` message.
 * `C-`: presented in the `channel_announcement` message, but always odd (optional).
 * `C+`: presented in the `channel_announcement` message, but always even (required).
 * `9`: presented in [BOLT 11](11-payment-encoding.md) invoices.

    FEATURE_NAME                                    # CONTEXT   # PRs
    ----------------------------------------------------------------- """
    OPTION_DATA_LOSS_PROTECT = 0                    # IN
    INITIAL_ROUTING_SYNC = 2                        # I
    OPTION_UPFRONT_SHUTDOWN_SCRIPT = 4              # IN
    GOSSIP_QUERIES = 6                              # IN
    VAR_ONION_OPTIN = 8                             # IN9
    GOSSIP_QUERIES_EX = 10                          # IN
    OPTION_STATIC_REMOTEKEY = 12                    # IN
    PAYMENT_SECRET = 14                             # IN9
    BASIC_MPP = 16                                  # IN9
    OPTION_SUPPORT_LARGE_CHANNEL = 18               # IN
    OPTION_ANCHOR_OUTPUTS = 20                      # IN
    OPTION_ANCHORS_ZERO_FEE_HTLC_TX = 22            # IN
    OPTION_SHUTDOWN_ANYSEGWIT = 26                  # IN
    OPTION_CHANNEL_TYPE = 44                        # IN
    OPTION_SCID_ALIAS = 46                          # IN
    OPTION_PAYMENT_METADATA = 48                    # 9
    OPTION_ZEROCONF = 50                            # IN

    OPTION_PROPOSED_ROUTE_BLINDING = 24             # IN9       #765 #798
    OPTION_PROPOSED_DUAL_FUND = 28                  # IN        #851 #1009
    OPTION_PROPOSED_ALTERNATIVE_FEERATES = 32       # IN        #1036
    OPTION_PROPOSED_QUIESCE = 34                    # IN        #869 #868
    OPTION_PROPOSED_ONION_MESSAGES = 38             # IN        #759
    OPTION_PROPOSED_WANT_PEER_BACKUP_STORAGE = 40   # IN        #881
    OPTION_PROPOSED_PROVIDE_PEER_BACKUP = 42        # IN        #881
    OPTION_PROPOSED_TRAMPOLINE_ROUTING = 56         # IN9       #836
    OPTION_PROPOSED_UPFRONT_FEE = 56                # IN9       #1052
    OPTION_PROPOSED_CLOSING_REJECTED = 60           # IN        #1016
    OPTION_PROPOSED_SPLICE = 62                     # IN        #863
    OPTION_PROPOSED_EXPERIMENTAL_SPLICE = 162       # IN        #863


def _parse_features(featurebytes):
    # featurebytes e.g.: [136, 160, 0, 8, 2, 105, 162]
    result = 0
    for byte in featurebytes:
        result <<= 8
        result |= byte
    return result


class GossipStoreMsgHeader(object):
    def __init__(self, buf: bytes, off: int):
        self.flags, self.length, self.crc, self.timestamp = struct.unpack('>HHII', buf)
        self.off = off
        self.deleted = (self.flags & GOSSIP_STORE_LEN_DELETED_BIT) != 0


class GossmapHalfchannel(object):
    """One direction of a GossmapChannel."""
    def __init__(self, channel: 'GossmapChannel', direction: int,
                 fields: Dict[str, Any], hdr: GossipStoreMsgHeader):
        assert direction in [0, 1], "direction can only be 0 or 1"
        self.channel = channel
        self.direction = direction
        self.source = channel.node1 if direction == 0 else channel.node2
        self.destination = channel.node2 if direction == 0 else channel.node1
        self.fields: Dict[str, Any] = fields
        self.hdr: GossipStoreMsgHeader = hdr

        self.timestamp: int = fields['timestamp']
        self.cltv_expiry_delta: int = fields['cltv_expiry_delta']
        self.htlc_minimum_msat: int = fields['htlc_minimum_msat']
        self.htlc_maximum_msat: Optional[int] = fields.get('htlc_maximum_msat', None)
        self.fee_base_msat: int = fields['fee_base_msat']
        self.fee_proportional_millionths: int = fields['fee_proportional_millionths']
        self.disabled = fields['channel_flags'] & 2 > 0

        # Cache the _scidd and hash to have faster operation later
        # Unfortunately the @final decorator only comes for python3.8
        self._scidd = f"{self.channel.scid}/{self.direction}"
        self._numscidd = direction << 63 | self.channel.scid.to_int()

    def __repr__(self):
        return f"GossmapHalfchannel[{self._scidd}]"

    def __eq__(self, other):
        if not isinstance(other, GossmapHalfchannel):
            return False
        return self._numscidd == other._numscidd

    def __str__(self):
        return self._scidd

    def __hash__(self):
        return self._numscidd


class GossmapNodeId(object):
    def __init__(self, buf: Union[bytes, str]):
        if isinstance(buf, str):
            buf = bytes.fromhex(buf)
        if len(buf) != 33 or (buf[0] != 2 and buf[0] != 3):
            raise ValueError("{} is not a valid node_id".format(buf.hex()))
        self.nodeid = buf

        self._hash = self.nodeid.__hash__()
        self._str = self.nodeid.hex()

    def to_pubkey(self) -> PublicKey:
        return PublicKey(self.nodeid)

    def __eq__(self, other):
        if not isinstance(other, GossmapNodeId):
            return False
        return self.nodeid.__eq__(other.nodeid)

    def __lt__(self, other):
        if not isinstance(other, GossmapNodeId):
            raise TypeError(f"Cannot compare GossmapNodeId with {type(other)}")
        return self.nodeid.__lt__(other.nodeid)  # yes, that works

    def __hash__(self):
        return self._hash

    def __repr__(self):
        return "GossmapNodeId[{}]".format(self.nodeid.hex())

    def __str__(self):
        return self._str

    @classmethod
    def from_str(cls, s: str):
        if s.startswith('0x'):
            s = s[2:]
        if len(s) != 66:
            raise ValueError(f"{s} is not a valid hexstring of a node_id")
        return cls(bytes.fromhex(s))


class GossmapChannel(object):
    """A channel: fields of channel_announcement are in .fields,
       optional updates are in .half_channels[0/1].fields """
    def __init__(self,
                 fields: Dict[str, Any],
                 scid: Union[ShortChannelId, str],
                 node1: 'GossmapNode',
                 node2: 'GossmapNode',
                 is_private: bool,
                 hdr: GossipStoreMsgHeader):
        self.fields: Dict[str, Any] = fields
        self.hdr: GossipStoreMsgHeader = hdr

        self.is_private = is_private
        self.scid = ShortChannelId.from_str(scid) if isinstance(scid, str) else scid
        self.node1 = node1
        self.node2 = node2
        self.satoshis = None
        self.half_channels: List[Optional[GossmapHalfchannel]] = [None, None]
        self.features = _parse_features(fields['features'])

    def _update_channel(self,
                        direction: int,
                        fields: Dict[str, Any],
                        hdr: GossipStoreMsgHeader):

        half = GossmapHalfchannel(self, direction, fields, hdr)
        self.half_channels[direction] = half

    def get_direction(self, direction: int):
        """ returns the GossmapHalfchannel if known by channel_update """
        assert direction in [0, 1], "direction can only be 0 or 1"
        return self.half_channels[direction]

    def __repr__(self):
        return "GossmapChannel[{}]".format(str(self.scid))

    def __str__(self):
        return str(self.scid)

    def __eq__(self, other):
        if not isinstance(other, GossmapChannel):
            return False
        return self.scid.__eq__(other.scid)

    def __hash__(self):
        return self.scid.__hash__()

    def has_feature(self, bit):
        return 3 << bit & self.features != 0

    def has_feature_compulsory(self, bit):
        return 1 << bit & self.features != 0

    def has_feature_optional(self, bit):
        return 2 << bit & self.features != 0

    def has_features(self, *bits):
        for bit in bits:
            if not self.has_feature(bit):
                return False
        return True

    def is_tor_only(c):
        """ Checks if a channel has TOR only nodes on both ends """
        return c.node1.is_tor_only() and c.node2.is_tor_only()


class GossmapNode(object):
    """A node: fields of node_announcement are in .fields,
       which can be None if there has been no node announcement.
       .channels is a list of the GossmapChannels attached to this node."""
    def __init__(self, node_id: Union[GossmapNodeId, bytes, str]):
        if isinstance(node_id, bytes) or isinstance(node_id, str):
            node_id = GossmapNodeId(node_id)
        self.fields: Optional[Dict[str, Any]] = None
        self.hdr: GossipStoreMsgHeader = None
        self.channels: List[GossmapChannel] = []
        self.node_id = node_id
        self.announced = False

        self._hash = self.node_id.__hash__()

    def __repr__(self):
        if hasattr(self, 'alias'):
            return f"GossmapNode[{self.node_id.nodeid.hex()}, \"{self.alias}\"]"
        return f"GossmapNode[{self.node_id.nodeid.hex()}]"

    def __eq__(self, other):
        if not isinstance(other, GossmapNode):
            return False
        return self.node_id.__eq__(other.node_id)

    def __lt__(self, other):
        if not isinstance(other, GossmapNode):
            raise TypeError(f"Cannot compare GossmapNode with {type(other)}")
        return self.node_id.__lt__(other.node_id)

    def __hash__(self):
        return self._hash

    def __str__(self):
        return str(self.node_id)

    def has_feature(self, bit):
        if not self.announced:
            return None
        return 3 << bit & self.features != 0

    def has_feature_compulsory(self, bit):
        if not self.announced:
            return None
        return 1 << bit & self.features != 0

    def has_feature_optional(self, bit):
        if not self.announced:
            return None
        return 2 << bit & self.features != 0

    def has_features(self, *bits):
        if not self.announced:
            return None
        for bit in bits:
            if not self.has_feature(bit):
                return False
        return True

    def _parse_addresses(self, data: bytes):
        """ parse address descriptors defined in bolts 07-routing-gossip.md """
        result = []
        try:
            stream = io.BytesIO(data)
            while stream.tell() < len(data):
                _type = int.from_bytes(stream.read(1), byteorder='big')
                if _type == 1:      # IPv4  length   6
                    ip = socket.inet_ntoa(stream.read(4))
                    port = int.from_bytes(stream.read(2), byteorder='big')
                    result.append(f"{ip}:{port}")
                elif _type == 2:    # IPv6  length  18
                    ip = socket.inet_ntop(socket.AF_INET6, stream.read(16))
                    port = int.from_bytes(stream.read(2), byteorder='big')
                    result.append(f"[{ip}]:{port}")
                elif _type == 3:    # TORv2 length  12 (deprecated)
                    stream.read(12)
                elif _type == 4:    # TORv3 length  37
                    addr = base64.b32encode(stream.read(35)).decode('ascii').lower()
                    port = int.from_bytes(stream.read(2), byteorder='big')
                    result.append(f"{addr}.onion:{port}")
                elif _type == 5:    # DNS   up to  258
                    hostname_len = int.from_bytes(stream.read(1), byteorder='big')
                    hostname = stream.read(hostname_len).decode('ascii')
                    port = int.from_bytes(stream.read(2), byteorder='big')
                    result.append(f"{hostname}:{port}")
                else:  # Stop parsing at the first unknown type
                    break
        # we simply pass exceptions and return what we were able to read so far
        except Exception:
            pass
        self.addresses = result

    def get_address_type(self, idx: int):
        """ I know this can be more sophisticated, but works """
        if not self.announced or len(self.addresses) <= idx:
            return None
        addrstr = self.addresses[idx]
        if ".onion:" in addrstr:
            return 'tor'
        if addrstr[0].isdigit():
            return 'ipv4'
        if addrstr.startswith("["):
            return 'ipv6'
        return 'dns'

    def has_clearnet(self):
        """ Checks if a node has one or more clearnet addresses """
        if not self.announced or len(self.addresses) == 0:
            return False
        for i in range(len(self.addresses)):
            if self.get_address_type(i) != 'tor':
                return True
        return False

    def has_tor(self):
        """ Checks if a node has one or more TOR addresses """
        if not self.announced or len(self.addresses) == 0:
            return False
        for i in range(len(self.addresses)):
            if self.get_address_type(i) == 'tor':
                return True
        return False

    def is_tor_only(self):
        """ Checks if a node has only TOR and no addresses announced """
        if not self.announced or len(self.addresses) == 0:
            return False
        for i in range(len(self.addresses)):
            if self.get_address_type(i) != 'tor':
                return False
        return True

    def is_tor_strict(self):
        """ Checks if a node is TOR only
            and is not publicly connected to any non-TOR nodes """
        if not self.is_tor_only():
            return False
        for c in self.channels:
            other = c.node1 if self != c.node1 else c.node2
            if other.has_tor():
                continue
            return False
        return True


class Gossmap(object):
    """Class to represent the gossip map of the network"""
    def __init__(self, store_filename: str = "gossip_store"):
        self.store_filename = store_filename
        self.store_file = open(store_filename, "rb")
        self.store_buf = bytes()
        self.bytes_read = 0
        self.nodes: Dict[GossmapNodeId, GossmapNode] = {}
        self.channels: Dict[ShortChannelId, GossmapChannel] = {}
        self._last_scid: Optional[str] = None
        version = self.store_file.read(1)[0]
        if (version & GOSSIP_STORE_MAJOR_VERSION_MASK) != GOSSIP_STORE_MAJOR_VERSION:
            raise ValueError("Invalid gossip store version {}".format(version))
        self.processing_time = 0
        self.orphan_channel_updates = set()
        self.refresh()

    def _new_channel(self,
                     fields: Dict[str, Any],
                     scid: ShortChannelId,
                     node1: GossmapNode,
                     node2: GossmapNode,
                     is_private: bool,
                     hdr: GossipStoreMsgHeader):
        c = GossmapChannel(fields, scid, node1, node2, is_private, hdr)
        self._last_scid = scid
        self.channels[scid] = c
        node1.channels.append(c)
        node2.channels.append(c)

    def _del_channel(self, scid: ShortChannelId):
        c = self.channels[scid]
        del self.channels[scid]
        c.node1.channels.remove(c)
        c.node2.channels.remove(c)
        # Beware self-channels n1-n1!
        if len(c.node1.channels) == 0 and c.node1 != c.node2:
            del self.nodes[c.node1.node_id]
        if len(c.node2.channels) == 0:
            del self.nodes[c.node2.node_id]

    def _add_channel(self, rec: bytes, is_private: bool, hdr: GossipStoreMsgHeader):
        fields = channel_announcement.read(io.BytesIO(rec[2:]), {})
        # Add nodes one the fly
        node1_id = GossmapNodeId(fields['node_id_1'])
        node2_id = GossmapNodeId(fields['node_id_2'])
        if node1_id not in self.nodes:
            self.nodes[node1_id] = GossmapNode(node1_id)
        if node2_id not in self.nodes:
            self.nodes[node2_id] = GossmapNode(node2_id)
        self._new_channel(fields,
                          ShortChannelId.from_int(fields['short_channel_id']),
                          self.get_node(node1_id), self.get_node(node2_id),
                          is_private, hdr)

    def _set_channel_amount(self, rec: bytes):
        """ Sets channel capacity of last added channel """
        sats, = struct.unpack(">Q", rec[2:])
        self.channels[self._last_scid].satoshis = sats

    def get_channel(self, short_channel_id: Union[ShortChannelId, str]):
        """ Resolves a channel by its short channel id """
        if isinstance(short_channel_id, str):
            short_channel_id = ShortChannelId.from_str(short_channel_id)
        return self.channels.get(short_channel_id)

    def get_halfchannel(self,
                        short_channel_id: Union[ShortChannelId, str],
                        direction: int):
        """ Returns a GossmapHalfchannel identified by a scid and direction. """
        assert short_channel_id is not None
        if isinstance(short_channel_id, str):
            short_channel_id = ShortChannelId.from_str(short_channel_id)
        assert direction in [0, 1], "direction can only be 0 or 1"
        channel = self.get_channel(short_channel_id)
        return channel.half_channels[direction]

    def get_neighbors_hc(self,
                         source: Union[GossmapNodeId, str, None] = None,
                         destination: Union[GossmapNodeId, str, None] = None,
                         depth: int = 0,
                         excludes: Union[Set[Any], List[Any]] = set()):
        """ Returns a set[GossmapHalfchannel]` from `source` or towards
            `destination` node ID. Using the optional `depth` greater than `0`
            will result in a second, third, ...  order list of connected
            channels towards or from that node.
            Note: only one of `source` or `destination` can be given. """
        assert (source is None) ^ (destination is None), "Only one of source or destination must be given"
        assert depth >= 0, "Depth cannot be smaller than 0"
        node = self.get_node(source if source else destination)
        assert node is not None, "source or destination unknown"
        if isinstance(excludes, List):
            excludes = set(excludes)

        # first get set of reachable nodes ...
        reachable = self.get_neighbors(source, destination, depth, excludes)
        # and iterate and check any each source/dest channel from here
        result = set()
        for node in reachable:
            for channel in node.channels:
                if channel in excludes:
                    continue
                other = channel.node1 if node != channel.node1 else channel.node2
                if other in reachable or other in excludes:
                    continue
                direction = 0
                if source is not None and node > other:
                    direction = 1
                if destination is not None and node < other:
                    direction = 1
                hc = channel.half_channels[direction]
                # skip excluded or non existent halfchannels
                if hc is None or hc in excludes:
                    continue
                result.add(hc)
        return result

    def get_node(self, node_id: Union[GossmapNodeId, str]):
        """ Resolves a node by its public key node_id """
        if isinstance(node_id, str):
            node_id = GossmapNodeId.from_str(node_id)
        return self.nodes.get(node_id)

    def get_neighbors(self,
                      source: Union[GossmapNodeId, str, None] = None,
                      destination: Union[GossmapNodeId, str, None] = None,
                      depth: int = 0,
                      excludes: Union[Set[Any], List[Any]] = set()):
        """ Returns a set of nodes within a given depth from a source node """
        assert (source is None) ^ (destination is None), "Only one of source or destination must be given"
        assert depth >= 0, "Depth cannot be smaller than 0"
        node = self.get_node(source if source else destination)
        assert node is not None, "source or destination unknown"
        if isinstance(excludes, List):
            excludes = set(excludes)

        result = set()
        result.add(node)
        inner = set()
        inner.add(node)
        while depth > 0:
            shell = set()
            for node in inner:
                for channel in node.channels:
                    if channel in excludes:  # skip excluded channels
                        continue
                    other = channel.node1 if channel.node1 != node else channel.node2
                    direction = 0
                    if source is not None and node > other:
                        direction = 1
                    if destination is not None and node < other:
                        direction = 1
                    if channel.half_channels[direction] is None:
                        continue  # one way channel in the wrong direction
                    halfchannel = channel.half_channels[direction]
                    if halfchannel in excludes:  # skip excluded halfchannels
                        continue
                    # skip excluded or already seen nodes
                    if other in excludes or other in inner or other in result:
                        continue
                    shell.add(other)
            if len(shell) == 0:
                break
            depth -= 1
            result.update(shell)
            inner = shell
        return result

    def _update_channel(self, rec: bytes, hdr: GossipStoreMsgHeader):
        fields = channel_update.read(io.BytesIO(rec[2:]), {})
        direction = fields['channel_flags'] & 1
        scid = ShortChannelId.from_int(fields['short_channel_id'])
        if scid in self.channels:
            c = self.channels[scid]
            c._update_channel(direction, fields, hdr)
        else:
            self.orphan_channel_updates.add(scid)

    def _add_node_announcement(self, rec: bytes, hdr: GossipStoreMsgHeader):
        fields = node_announcement.read(io.BytesIO(rec[2:]), {})
        node_id = GossmapNodeId(fields['node_id'])
        if node_id not in self.nodes:
            self.nodes[node_id] = GossmapNode(node_id)
        node = self.nodes[node_id]
        node.fields = fields
        node.hdr = hdr

        # read metadata
        node.features = _parse_features(fields['features'])
        node.timestamp = fields['timestamp']
        node.alias = bytes(fields['alias']).decode('utf-8')
        node.rgb = fields['rgb_color']
        node._parse_addresses(bytes(fields['addresses']))
        node.announced = True

    def reopen_store(self):
        assert False, "FIXME: Implement!"

    def _remove_channel_by_deletemsg(self, rec: bytes):
        scidint, = struct.unpack(">Q", rec[2:])
        scid = ShortChannelId.from_int(scidint)
        # It might have already been deleted when we skipped it.
        if scid in self.channels:
            self._del_channel(scid)

    def _pull_bytes(self, length: int) -> bool:
        """Pull bytes from file into our internal buffer"""
        if len(self.store_buf) < length:
            self.store_buf += self.store_file.read(length - len(self.store_buf))
        self.bytes_read += len(self.store_buf)
        return len(self.store_buf) >= length

    def _read_record(self) -> Optional[bytes]:
        """If a whole record is not in the file, returns None.
        If deleted, returns empty."""
        off = self.bytes_read + 1
        if not self._pull_bytes(12):
            return None, None
        hdr = GossipStoreMsgHeader(self.store_buf[:12], off)
        if not self._pull_bytes(12 + hdr.length):
            return None, hdr
        rec = self.store_buf[12:]
        self.store_buf = bytes()
        return rec, hdr

    def refresh(self):
        """Catch up with any changes to the gossip store"""
        start_time = time.time()
        while True:
            rec, hdr = self._read_record()
            if rec is None:  # EOF
                break
            if hdr.deleted:  # Skip deleted records
                continue

            rectype, = struct.unpack(">H", rec[:2])
            if rectype == channel_announcement.number:
                self._add_channel(rec, False, hdr)
            elif rectype == WIRE_GOSSIP_STORE_PRIVATE_CHANNEL:
                hdr.off += 2 + 8 + 2
                self._add_channel(rec[2 + 8 + 2:], True, hdr)
            elif rectype == WIRE_GOSSIP_STORE_CHANNEL_AMOUNT:
                self._set_channel_amount(rec)
            elif rectype == channel_update.number:
                self._update_channel(rec, hdr)
            elif rectype == WIRE_GOSSIP_STORE_PRIVATE_UPDATE:
                hdr.off += 2 + 2
                self._update_channel(rec[2 + 2:], hdr)
            elif rectype == WIRE_GOSSIP_STORE_DELETE_CHAN:
                self._remove_channel_by_deletemsg(rec)
            elif rectype == node_announcement.number:
                self._add_node_announcement(rec, hdr)
            elif rectype == WIRE_GOSSIP_STORE_ENDED:
                self.reopen_store()
            else:
                continue
        self.processing_time += time.time() - start_time
