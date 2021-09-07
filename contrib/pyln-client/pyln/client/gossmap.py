#! /usr/bin/python3

from pyln.spec.bolt7 import (channel_announcement, channel_update,
                             node_announcement)
from typing import Dict, List, Optional

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


class GossipStoreHeader(object):
    def __init__(self, buf: bytes):
        length, self.crc, self.timestamp = struct.unpack('>III', buf)
        self.deleted = (length & GOSSIP_STORE_LEN_DELETED_BIT) != 0
        self.length = (length & GOSSIP_STORE_LEN_MASK)


# FIXME!
class short_channel_id(int):
    pass


class point(bytes):
    pass


class GossmapChannel(object):
    def __init__(self,
                 announce: bytes,
                 announce_offset: int,
                 scid,
                 node1_id: point,
                 node2_id: point,
                 is_private: bool):
        self.announce = announce
        self.announce_offset = announce_offset
        self.is_private = is_private
        self.scid = scid
        self.node1_id = node1_id
        self.node2_id = node2_id
        self.updates: List[Optional[bytes]] = [None, None]
        self.updates_offset: List[Optional[int]] = [None, None]


class GossmapNode(object):
    def __init__(self, node_id: point):
        self.announce = None
        self.announce_offset = None
        self.channels = []
        self.node_id = node_id


class Gossmap(object):
    """Class to represent the gossip map of the network"""
    def __init__(self, store_filename: str = "gossip_store"):
        self.store_filename = store_filename
        self.store_file = open(store_filename, "rb")
        self.store_buf = bytes()
        self.nodes: Dict[point, GossmapNode] = {}
        self.channels: Dict[short_channel_id, GossmapChannel] = {}
        version = self.store_file.read(1)
        if version[0] != GOSSIP_STORE_VERSION:
            raise ValueError("Invalid gossip store version {}".format(version))
        self.bytes_read = 1
        self.refresh()

    def _new_channel(self,
                     announce: bytes,
                     announce_offset: int,
                     scid: short_channel_id,
                     node1_id: point,
                     node2_id: point,
                     is_private: bool):
        c = GossmapChannel(announce, announce_offset,
                           scid, node1_id, node2_id,
                           is_private)
        if node1_id not in self.nodes:
            self.nodes[node1_id] = GossmapNode(node1_id)
        if node2_id not in self.nodes:
            self.nodes[node2_id] = GossmapNode(node2_id)

        self.channels[scid] = c
        self.nodes[node1_id].channels.append(c)
        self.nodes[node2_id].channels.append(c)

    def _del_channel(self, scid: short_channel_id):
        c = self.channels[scid]
        n1 = self.nodes[c.node1_id]
        n2 = self.nodes[c.node2_id]
        n1.channels.remove(c)
        n2.channels.remove(c)
        # Beware self-channels n1-n1!
        if len(n1.channels) == 0 and n1 != n2:
            del self.nodes[c.node1_id]
        if len(n2.channels):
            del self.nodes[c.node2_id]

    def add_channel(self, rec: bytes, off: int, is_private: bool):
        fields = channel_announcement.read(io.BytesIO(rec[2:]), {})
        self._new_channel(rec, off, fields['short_channel_id'],
                          fields['node_id_1'], fields['node_id_2'],
                          is_private)

    def update_channel(self, rec: bytes, off: int):
        fields = channel_update.read(io.BytesIO(rec[2:]), {})
        direction = fields['channel_flags'] & 1
        c = self.channels[fields['short_channel_id']]
        c.updates[direction] = rec
        c.updates_offset = off

    def add_node_announcement(self, rec: bytes, off: int):
        fields = node_announcement.read(io.BytesIO(rec[2:]), {})
        self.nodes[fields['node_id']].announce = rec
        self.nodes[fields['node_id']].announce_offset = off

    def reopen_store(self):
        assert False

    def remove_channel_by_deletemsg(self, rec: bytes):
        scid, = struct.unpack(">Q", rec[2:])
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
                self.add_channel(rec, off, False)
            elif rectype == WIRE_GOSSIP_STORE_PRIVATE_CHANNEL:
                self.add_channel(rec[2 + 8 + 2:], off + 2 + 8 + 2, True)
            elif rectype == channel_update.number:
                self.update_channel(rec, off)
            elif rectype == WIRE_GOSSIP_STORE_PRIVATE_UPDATE:
                self.update_channel(rec[2 + 2:], off + 2 + 2)
            elif rectype == WIRE_GOSSIP_STORE_DELETE_CHAN:
                self.remove_channel_by_deletemsg(rec)
            elif rectype == node_announcement.number:
                self.add_node_announcement(rec, off)
            elif rectype == WIRE_GOSSIP_STORE_ENDED:
                self.reopen_store()
            else:
                continue
