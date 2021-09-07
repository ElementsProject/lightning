#! /usr/bin/python3

from pyln.spec.bolt7 import (channel_announcement, channel_update,
                             node_announcement)
from pyln.proto import ShortChannelId, PublicKey
from typing import Any, Dict, List, Optional, Union, cast

import io
import struct

# These duplicate constants in lightning/common/gossip_store.h
GOSSIP_STORE_VERSION = 9
GOSSIP_STORE_LEN_DELETED_BIT = 0x80000000
GOSSIP_STORE_LEN_PUSH_BIT = 0x40000000
GOSSIP_STORE_LEN_MASK = (~(GOSSIP_STORE_LEN_PUSH_BIT
                           | GOSSIP_STORE_LEN_DELETED_BIT))

# These duplicate constants in lightning/gossipd/gossip_store_wiregen.h
WIRE_GOSSIP_STORE_PRIVATE_CHANNEL = 4104
WIRE_GOSSIP_STORE_PRIVATE_UPDATE = 4102
WIRE_GOSSIP_STORE_DELETE_CHAN = 4103
WIRE_GOSSIP_STORE_ENDED = 4105
WIRE_GOSSIP_STORE_CHANNEL_AMOUNT = 4101


class GossipStoreHeader(object):
    def __init__(self, buf: bytes):
        length, self.crc, self.timestamp = struct.unpack('>III', buf)
        self.deleted = (length & GOSSIP_STORE_LEN_DELETED_BIT) != 0
        self.length = (length & GOSSIP_STORE_LEN_MASK)


class GossmapHalfchannel(object):
    """One direction of a GossmapChannel."""
    def __init__(self, channel: 'GossmapChannel', direction: int,
                 timestamp: int, cltv_expiry_delta: int,
                 htlc_minimum_msat: int, htlc_maximum_msat: int,
                 fee_base_msat: int, fee_proportional_millionths: int):

        self.channel = channel
        self.direction = direction
        self.source = channel.node1 if direction == 0 else channel.node2
        self.destination = channel.node2 if direction == 0 else channel.node1

        self.timestamp: int = timestamp
        self.cltv_expiry_delta: int = cltv_expiry_delta
        self.htlc_minimum_msat: int = htlc_minimum_msat
        self.htlc_maximum_msat: Optional[int] = htlc_maximum_msat
        self.fee_base_msat: int = fee_base_msat
        self.fee_proportional_millionths: int = fee_proportional_millionths

    def __repr__(self):
        return "GossmapHalfchannel[{}x{}]".format(str(self.channel.scid), self.direction)


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
    """A channel: fields of channel_announcement are in .fields, optional updates are in .updates_fields, which can be None if there has been no channel update."""
    def __init__(self,
                 fields: Dict[str, Any],
                 announce_offset: int,
                 scid,
                 node1: 'GossmapNode',
                 node2: 'GossmapNode',
                 is_private: bool):
        self.fields = fields
        self.announce_offset = announce_offset
        self.is_private = is_private
        self.scid = scid
        self.node1 = node1
        self.node2 = node2
        self.updates_fields: List[Optional[Dict[str, Any]]] = [None, None]
        self.updates_offset: List[Optional[int]] = [None, None]
        self.satoshis = None
        self.half_channels: List[Optional[GossmapHalfchannel]] = [None, None]

    def _update_channel(self,
                        direction: int,
                        fields: Dict[str, Any],
                        off: int):
        self.updates_fields[direction] = fields
        self.updates_offset[direction] = off

        half = GossmapHalfchannel(self, direction,
                                  fields['timestamp'],
                                  fields['cltv_expiry_delta'],
                                  fields['htlc_minimum_msat'],
                                  fields.get('htlc_maximum_msat', None),
                                  fields['fee_base_msat'],
                                  fields['fee_proportional_millionths'])
        self.half_channels[direction] = half

    def get_direction(self, direction: int):
        """ returns the GossmapHalfchannel if known by channel_update """
        if not 0 <= direction <= 1:
            raise ValueError("direction can only be 0 or 1")
        return self.half_channels[direction]

    def __repr__(self):
        return "GossmapChannel[{}]".format(str(self.scid))


class GossmapNode(object):
    """A node: fields of node_announcement are in .announce_fields, which can be None of there has been no node announcement.

.channels is a list of the GossmapChannels attached to this node.
"""
    def __init__(self, node_id: Union[GossmapNodeId, bytes, str]):
        if isinstance(node_id, bytes) or isinstance(node_id, str):
            node_id = GossmapNodeId(node_id)
        self.announce_fields: Optional[Dict[str, Any]] = None
        self.announce_offset: Optional[int] = None
        self.channels: List[GossmapChannel] = []
        self.node_id = node_id

    def __repr__(self):
        return "GossmapNode[{}]".format(self.node_id.nodeid.hex())

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
        self.nodes: Dict[GossmapNodeId, GossmapNode] = {}
        self.channels: Dict[ShortChannelId, GossmapChannel] = {}
        self._last_scid: Optional[str] = None
        version = self.store_file.read(1)
        if version[0] != GOSSIP_STORE_VERSION:
            raise ValueError("Invalid gossip store version {}".format(int(version)))
        self.bytes_read = 1
        self.refresh()

    def _new_channel(self,
                     fields: Dict[str, Any],
                     announce_offset: int,
                     scid: ShortChannelId,
                     node1: GossmapNode,
                     node2: GossmapNode,
                     is_private: bool):
        c = GossmapChannel(fields, announce_offset,
                           scid, node1, node2,
                           is_private)
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

    def _add_channel(self, rec: bytes, off: int, is_private: bool):
        fields = channel_announcement.read(io.BytesIO(rec[2:]), {})
        # Add nodes one the fly
        node1_id = GossmapNodeId(fields['node_id_1'])
        node2_id = GossmapNodeId(fields['node_id_2'])
        if node1_id not in self.nodes:
            self.nodes[node1_id] = GossmapNode(node1_id)
        if node2_id not in self.nodes:
            self.nodes[node2_id] = GossmapNode(node2_id)
        self._new_channel(fields, off,
                          ShortChannelId.from_int(fields['short_channel_id']),
                          self.get_node(node1_id), self.get_node(node2_id),
                          is_private)

    def _set_channel_amount(self, rec: bytes):
        """ Sets channel capacity of last added channel """
        sats, = struct.unpack(">Q", rec[2:])
        self.channels[self._last_scid].satoshis = sats

    def get_channel(self, short_channel_id: ShortChannelId):
        """ Resolves a channel by its short channel id """
        if isinstance(short_channel_id, str):
            short_channel_id = ShortChannelId.from_str(short_channel_id)
        return self.channels.get(short_channel_id)

    def get_node(self, node_id: Union[GossmapNodeId, str]):
        """ Resolves a node by its public key node_id """
        if isinstance(node_id, str):
            node_id = GossmapNodeId.from_str(node_id)
        return self.nodes.get(cast(GossmapNodeId, node_id))

    def _update_channel(self, rec: bytes, off: int):
        fields = channel_update.read(io.BytesIO(rec[2:]), {})
        direction = fields['channel_flags'] & 1
        c = self.channels[ShortChannelId.from_int(fields['short_channel_id'])]
        c._update_channel(direction, fields, off)

    def _add_node_announcement(self, rec: bytes, off: int):
        fields = node_announcement.read(io.BytesIO(rec[2:]), {})
        node_id = GossmapNodeId(fields['node_id'])
        self.nodes[node_id].announce_fields = fields
        self.nodes[node_id].announce_offset = off

    def reopen_store(self):
        """FIXME: Implement!"""
        assert False

    def _remove_channel_by_deletemsg(self, rec: bytes):
        scidint, = struct.unpack(">Q", rec[2:])
        scid = ShortChannelId.from_int(scidint)
        # It might have already been deleted when we skipped it.
        if scid in self.channels:
            self._del_channel(scid)

    def _pull_bytes(self, length: int) -> bool:
        """Pull bytes from file into our internal buffer"""
        if len(self.store_buf) < length:
            self.store_buf += self.store_file.read(length
                                                   - len(self.store_buf))
        return len(self.store_buf) >= length

    def _read_record(self) -> Optional[bytes]:
        """If a whole record is not in the file, returns None.
        If deleted, returns empty."""
        if not self._pull_bytes(12):
            return None
        hdr = GossipStoreHeader(self.store_buf[:12])
        if not self._pull_bytes(12 + hdr.length):
            return None
        self.bytes_read += len(self.store_buf)
        ret = self.store_buf[12:]
        self.store_buf = bytes()
        if hdr.deleted:
            ret = bytes()
        return ret

    def refresh(self):
        """Catch up with any changes to the gossip store"""
        while True:
            off = self.bytes_read
            rec = self._read_record()
            # EOF?
            if rec is None:
                break
            # Deleted?
            if len(rec) == 0:
                continue

            rectype, = struct.unpack(">H", rec[:2])
            if rectype == channel_announcement.number:
                self._add_channel(rec, off, False)
            elif rectype == WIRE_GOSSIP_STORE_PRIVATE_CHANNEL:
                self._add_channel(rec[2 + 8 + 2:], off + 2 + 8 + 2, True)
            elif rectype == WIRE_GOSSIP_STORE_CHANNEL_AMOUNT:
                self._set_channel_amount(rec)
            elif rectype == channel_update.number:
                self._update_channel(rec, off)
            elif rectype == WIRE_GOSSIP_STORE_PRIVATE_UPDATE:
                self._update_channel(rec[2 + 2:], off + 2 + 2)
            elif rectype == WIRE_GOSSIP_STORE_DELETE_CHAN:
                self._remove_channel_by_deletemsg(rec)
            elif rectype == node_announcement.number:
                self._add_node_announcement(rec, off)
            elif rectype == WIRE_GOSSIP_STORE_ENDED:
                self.reopen_store()
            else:
                continue
