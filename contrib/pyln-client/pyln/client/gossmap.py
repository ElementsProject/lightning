#! /usr/bin/python3

from pyln.spec.bolt7 import (channel_announcement, channel_update,
                             node_announcement)
from pyln.proto import ShortChannelId, PublicKey
from typing import Any, Dict, List, Optional, Union

import io
import struct

# These duplicate constants in lightning/common/gossip_store.h
GOSSIP_STORE_MAJOR_VERSION = (0 << 5)
GOSSIP_STORE_MAJOR_VERSION_MASK = 0xE0
GOSSIP_STORE_LEN_DELETED_BIT = 0x8000
GOSSIP_STORE_LEN_PUSH_BIT = 0x4000
GOSSIP_STORE_LEN_RATELIMIT_BIT = 0x2000
GOSSIP_STORE_ZOMBIE_BIT = 0x1000

# These duplicate constants in lightning/gossipd/gossip_store_wiregen.h
WIRE_GOSSIP_STORE_PRIVATE_CHANNEL = 4104
WIRE_GOSSIP_STORE_PRIVATE_UPDATE = 4102
WIRE_GOSSIP_STORE_DELETE_CHAN = 4103
WIRE_GOSSIP_STORE_ENDED = 4105
WIRE_GOSSIP_STORE_CHANNEL_AMOUNT = 4101


class GossipStoreHeader(object):
    def __init__(self, buf: bytes, off: int):
        self.flags, self.length, self.crc, self.timestamp = struct.unpack('>HHII', buf)
        self.off = off
        self.deleted = (self.flags & GOSSIP_STORE_LEN_DELETED_BIT) != 0
        self.ratelimit = (self.flags & GOSSIP_STORE_LEN_RATELIMIT_BIT) != 0
        self.zombie = (self.flags & GOSSIP_STORE_ZOMBIE_BIT) != 0


class GossmapHalfchannel(object):
    """One direction of a GossmapChannel."""
    def __init__(self, channel: 'GossmapChannel', direction: int,
                 fields: Dict[str, Any], hdr: GossipStoreHeader):
        assert direction in [0, 1], "direction can only be 0 or 1"
        self.channel = channel
        self.direction = direction
        self.source = channel.node1 if direction == 0 else channel.node2
        self.destination = channel.node2 if direction == 0 else channel.node1
        self.fields: Dict[str, Any] = fields
        self.hdr: GossipStoreHeader = hdr

        self.timestamp: int = fields['timestamp']
        self.cltv_expiry_delta: int = fields['cltv_expiry_delta']
        self.htlc_minimum_msat: int = fields['htlc_minimum_msat']
        self.htlc_maximum_msat: Optional[int] = fields.get('htlc_maximum_msat', None)
        self.fee_base_msat: int = fields['fee_base_msat']
        self.fee_proportional_millionths: int = fields['fee_proportional_millionths']

    def __repr__(self):
        return f"GossmapHalfchannel[{self._scidd}]"


class GossmapNodeId(object):
    def __init__(self, buf: Union[bytes, str]):
        if isinstance(buf, str):
            buf = bytes.fromhex(buf)
        if len(buf) != 33 or (buf[0] != 2 and buf[0] != 3):
            raise ValueError("{} is not a valid node_id".format(buf.hex()))
        self.nodeid = buf

    def to_pubkey(self) -> PublicKey:
        return PublicKey(self.nodeid)

    def __eq__(self, other):
        if not isinstance(other, GossmapNodeId):
            return False
        return self.nodeid.__eq__(other.nodeid)

    def __lt__(self, other):
        if not isinstance(other, GossmapNodeId):
            raise ValueError(f"Cannot compare GossmapNodeId with {type(other)}")
        return self.nodeid.__lt__(other.nodeid)  # yes, that works

    def __hash__(self):
        return self.nodeid.__hash__()

    def __repr__(self):
        return "GossmapNodeId[{}]".format(self.nodeid.hex())

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
                 hdr: GossipStoreHeader):
        self.fields: Dict[str, Any] = fields
        self.hdr: GossipStoreHeader = hdr

        self.is_private = is_private
        self.scid = ShortChannelId.from_str(scid) if isinstance(scid, str) else scid
        self.node1 = node1
        self.node2 = node2
        self.satoshis = None
        self.half_channels: List[Optional[GossmapHalfchannel]] = [None, None]

    def _update_channel(self,
                        direction: int,
                        fields: Dict[str, Any],
                        hdr: GossipStoreHeader):

        half = GossmapHalfchannel(self, direction, fields, hdr)
        self.half_channels[direction] = half

    def get_direction(self, direction: int):
        """ returns the GossmapHalfchannel if known by channel_update """
        assert direction in [0, 1], "direction can only be 0 or 1"
        return self.half_channels[direction]

    def __repr__(self):
        return "GossmapChannel[{}]".format(str(self.scid))


class GossmapNode(object):
    """A node: fields of node_announcement are in .fields,
       which can be None if there has been no node announcement.
       .channels is a list of the GossmapChannels attached to this node."""
    def __init__(self, node_id: Union[GossmapNodeId, bytes, str]):
        if isinstance(node_id, bytes) or isinstance(node_id, str):
            node_id = GossmapNodeId(node_id)
        self.fields: Optional[Dict[str, Any]] = None
        self.hdr: GossipStoreHeader = None
        self.channels: List[GossmapChannel] = []
        self.node_id = node_id

    def __repr__(self):
        return f"GossmapNode[{self.node_id.nodeid.hex()}]"

    def __eq__(self, other):
        if not isinstance(other, GossmapNode):
            return False
        return self.node_id.__eq__(other.node_id)

    def __lt__(self, other):
        if not isinstance(other, GossmapNode):
            raise ValueError(f"Cannot compare GossmapNode with {type(other)}")
        return self.node_id.__lt__(other.node_id)


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
                     hdr: GossipStoreHeader):
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

    def _add_channel(self, rec: bytes, is_private: bool, hdr: GossipStoreHeader):
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

    def get_node(self, node_id: Union[GossmapNodeId, str]):
        """ Resolves a node by its public key node_id """
        if isinstance(node_id, str):
            node_id = GossmapNodeId.from_str(node_id)
        return self.nodes.get(node_id)

    def _update_channel(self, rec: bytes, hdr: GossipStoreHeader):
        fields = channel_update.read(io.BytesIO(rec[2:]), {})
        direction = fields['channel_flags'] & 1
        scid = ShortChannelId.from_int(fields['short_channel_id'])
        if scid in self.channels:
            c = self.channels[scid]
            c._update_channel(direction, fields, hdr)
        else:
            self.orphan_channel_updates.add(scid)

    def _add_node_announcement(self, rec: bytes, hdr: GossipStoreHeader):
        fields = node_announcement.read(io.BytesIO(rec[2:]), {})
        node_id = GossmapNodeId(fields['node_id'])
        if node_id not in self.nodes:
            self.nodes[node_id] = GossmapNode(node_id)
        node = self.nodes[node_id]
        node.fields = fields
        node.hdr = hdr

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
        hdr = GossipStoreHeader(self.store_buf[:12], off)
        if not self._pull_bytes(12 + hdr.length):
            return None, hdr
        rec = self.store_buf[12:]
        self.store_buf = bytes()
        return rec, hdr

    def refresh(self):
        """Catch up with any changes to the gossip store"""
        while True:
            rec, hdr = self._read_record()
            if rec is None:  # EOF
                break
            if hdr.deleted:  # Skip deleted records
                continue
            if hdr.zombie:
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
