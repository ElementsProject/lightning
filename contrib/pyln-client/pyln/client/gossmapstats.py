from pyln.client import Gossmap, GossmapChannel, GossmapNode, GossmapHalfchannel, LnFeatureBits
from typing import Iterable, List, Optional, Callable

import operator
import statistics


class GossmapStats(object):
    def __init__(self, g: Gossmap):
        self.g = g

    # First the generic filter functions
    def filter_nodes(self, predicate: Callable[[GossmapNode], bool], nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """ Filter nodes using an arbitrary function or lamda predicate. """
        if nodes is None:
            nodes = self.g.nodes.values()
        return [n for n in nodes if predicate(n)]

    def filter_channels(self, predicate: Callable[[GossmapChannel], bool], channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters channels using an arbitrary function or lambda predicate. """
        if channels is None:
            channels = self.g.channels.values()
        return [c for c in channels if predicate(c)]

    def filter_halfchannels(self, predicate: Callable[[GossmapHalfchannel], bool], channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapHalfchannel]:
        """ Filters half-channels using an arbitrary function or lambda predicate. """
        if channels is None:
            channels = self.g.channels.values()
        hc0 = [c.half_channels[0] for c in channels if c.half_channels[0] is not None and predicate(c.half_channels[0])]
        hc1 = [c.half_channels[1] for c in channels if c.half_channels[1] is not None and predicate(c.half_channels[1])]
        return hc0 + hc1

    # Now a bunch of predefined specific filter methods
    def filter_nodes_unannounced(self, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """ Filters nodes that are only known by a channel, i.e. missing a node_announcement.
            Usually happens when a peer has been offline for a while. """
        return self.filter_nodes(lambda n: not n.announced, nodes)

    def filter_nodes_feature(self, bit, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """Filters nodes based on node_announcement feature bits. """
        return self.filter_nodes(lambda n: n.announced and 3 << bit & n.features != 0, nodes)

    def filter_nodes_feature_compulsory(self, bit, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """Filters nodes based on node_announcement feature bits. """
        return self.filter_nodes(lambda n: n.announced and 1 << bit & n.features != 0, nodes)

    def filter_nodes_feature_optional(self, bit, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """Filters nodes based on node_announcement feature bits. """
        return self.filter_nodes(lambda n: n.announced and 2 << bit & n.features != 0, nodes)

    def filter_nodes_address_type(self, typestr, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """ Filters nodes having at least one address of typetr: 'ipv4', 'ipv6', 'tor' or 'dns'. """
        return self.filter_nodes(lambda n: n.announced and len([idx for idx in range(len(n.addresses)) if n.get_address_type(idx) == typestr]) > 0, nodes)

    def filter_nodes_tor_only(self, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """ Filters nodes that only announce TOR addresses, if any. """
        return self.filter_nodes(lambda n: n.is_tor_only(), nodes)

    def filter_nodes_tor_strict(self, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """ Filters TOR only nodes that don't (or possibly can't) connect to non-TOR nodes. """
        return self.filter_nodes(lambda n: n.is_tor_strict(), nodes)

    def filter_nodes_no_addresses(self, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """ Filters nodes that don't announce any addresses. """
        return self.filter_nodes(lambda n: n.announced and len(n.addresses) == 0, nodes)

    def filter_nodes_channel_count(self, count, op=operator.ge, nodes: Optional[Iterable[GossmapNode]] = None) -> List[GossmapNode]:
        """ Filters nodes by its channel count (default op: being greater or eaqual). """
        return self.filter_nodes(lambda n: op(len(n.channels), count), nodes)

    def filter_channels_feature(self, bit, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters channels based on channel_announcement feature bits. """
        return self.filter_channels(lambda c: 3 << bit & c.features != 0, channels)

    def filter_channels_feature_compulsory(self, bit, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters channels based on channel_announcement feature bits. """
        return self.filter_channels(lambda c: 1 << bit & c.features != 0, channels)

    def filter_channels_feature_optional(self, bit, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters channels based on channel_announcement feature bits. """
        return self.filter_channels(lambda c: 2 << bit & c.features != 0, channels)

    def filter_channels_unidirectional(self, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters channels that are known only in one direction, i.e. other peer seems offline for a long time. """
        return self.filter_channels(lambda c: c.half_channels[0] is None or c.half_channels[1] is None, channels)

    def filter_channels_nosatoshis(self, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters channels with missing WIRE_GOSSIP_STORE_CHANNEL_AMOUNT. This should not happen. """
        return self.filter_channels(lambda c: c.satoshis is None, channels)

    def filter_channels_tor_only(self, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters all channels that are connected to TOR only nodes on both ends. """
        return self.filter_channels(lambda c: c.is_tor_only(), channels)

    def filter_channels_capacity(self, satoshis, op=operator.ge, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filter channels by its capacity (default op: being greater or equal). """
        return self.filter_channels(lambda c: c.satoshis is not None and op(c.satoshis, satoshis), channels)

    def filter_channels_disabled_bidirectional(self, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters channels that are disabled in both directions. """
        return self.filter_channels(lambda c: c.half_channels[0] is not None and c.half_channels[0].disabled and c.half_channels[1] is not None and c.half_channels[1].disabled, channels)

    def filter_channels_disabled_unidirectional(self, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapChannel]:
        """ Filters channels that are disabled only in one direction. """
        if channels is None:
            channels = self.g.channels.values()
        hc0 = [c for c in channels if c.half_channels[0] is not None and c.half_channels[0].disabled and (c.half_channels[1] is None or not c.half_channels[1].disabled)]
        hc1 = [c for c in channels if c.half_channels[1] is not None and c.half_channels[1].disabled and (c.half_channels[0] is None or not c.half_channels[0].disabled)]
        return hc0 + hc1

    def filter_halfchannels_fee_base(self, msat, op=operator.le, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapHalfchannel]:
        """ Filters half-channels by its base fee (default op: being lower or equal). """
        return self.filter_halfchannels(lambda hc: op(hc.fee_base_msat, msat), channels)

    def filter_halfchannels_fee_ppm(self, msat, op=operator.le, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapHalfchannel]:
        """ Filters half-channels by its ppm fee (default op: being lower or equal). """
        return self.filter_halfchannels(lambda hc: op(hc.fee_proportional_millionths, msat), channels)

    def filter_halfchannels_disabled(self, channels: Optional[Iterable[GossmapChannel]] = None) -> List[GossmapHalfchannel]:
        """ Filters half-channels that are disabled. """
        return self.filter_halfchannels(lambda hc: hc.disabled, channels)

    def quantiles_nodes_channel_count(self, tiles=100, nodes: Optional[Iterable[GossmapNode]] = None) -> List[float]:
        if nodes is None:
            nodes = self.g.nodes.values()
        return statistics.quantiles([len(n.channels) for n in nodes], n=tiles)

    def quantiles_channels_capacity(self, tiles=100, channels: Optional[Iterable[GossmapChannel]] = None) -> List[float]:
        if channels is None:
            channels = self.g.channels.values()
        return statistics.quantiles([c.satoshis for c in channels if c.satoshis is not None], n=tiles)

    def quantiles_halfchannels_fee_base(self, tiles=100, channels: Optional[Iterable[GossmapChannel]] = None) -> List[float]:
        if channels is None:
            channels = self.g.channels.values()
        hc0 = [c.half_channels[0].fee_base_msat for c in channels if c.half_channels[0] is not None]
        hc1 = [c.half_channels[1].fee_base_msat for c in channels if c.half_channels[1] is not None]
        return statistics.quantiles(hc0 + hc1, n=tiles)

    def quantiles_halfchannels_fee_ppm(self, tiles=100, channels: Optional[Iterable[GossmapChannel]] = None) -> List[float]:
        if channels is None:
            channels = self.g.channels.values()
        hc0 = [c.half_channels[0].fee_proportional_millionths for c in channels if c.half_channels[0] is not None]
        hc1 = [c.half_channels[1].fee_proportional_millionths for c in channels if c.half_channels[1] is not None]
        return statistics.quantiles(hc0 + hc1, n=tiles)

    def print_stats(self):
        print("#### pyln-client gossmap stats ####")
        print(f"The gossip_store has a total of {len(self.g.nodes)} nodes and {len(self.g.channels)} channels.")
        print(f"Total processing time was {self.g.processing_time} seconds.")
        print("")

        print("CONSISTENCY")
        print(f" - {len(self.filter_nodes_unannounced())} orphan nodes without a node_announcement, only known from a channel_announcement.")
        print(f" - {len(self.g.orphan_channel_updates)} orphan channel_updates without a prior channel_announcement.")
        print(f" - {len(self.filter_channels_nosatoshis())} channels without capacity (missing WIRE_GOSSIP_STORE_CHANNEL_AMOUNT). Should be 0.")
        print("")

        print("STRUCTURE")
        print(f" - {len(self.filter_channels_unidirectional())} channels that are known only in one direction, other peer seems offline for a long time.")
        print(f" - {len(self.filter_halfchannels_disabled())} total disabled half-channels.")
        print(f" - {len(self.filter_channels_disabled_unidirectional())} channels are only disabled in one direction.")
        print(f" - {len(self.filter_channels_disabled_bidirectional())} channels are disabled in both directions.")
        print(f" - channel_count per node quantiles(10): {self.quantiles_nodes_channel_count(10)}.")
        print(f" - channel_capacity quantiles(10): {self.quantiles_channels_capacity(10)}.")
        print("")

        print("ADDRESSES")
        print(f" - {len(self.filter_nodes_address_type('ipv4'))} nodes announce IPv4 addresses.")
        print(f" - {len(self.filter_nodes_address_type('ipv6'))} nodes announce IPv6 addresses.")
        print(f" - {len(self.filter_nodes_address_type('tor'))} nodes announce TOR addresses.")
        print(f" - {len(self.filter_nodes_address_type('dns'))} nodes announce DNS addresses.")
        print(f" - {len(self.filter_nodes_no_addresses())} don't announce any address.")
        print(f" - {len(self.filter_nodes_tor_only())} nodes announce only TOR addresses, if any.")
        print(f" - {len(self.filter_nodes_tor_strict())} nodes announce only TOR addresses and don't, or possibly can't, connect to non-TOR nodes.")
        print(f" - {len(self.filter_channels_tor_only())} channels are connected TOR only nodes on both ends.")
        print("")

        print("FEES")
        print(f" - {len(self.filter_halfchannels_fee_base(0))} half-channels have a base_fee of 0msat.")
        print(f" - {len(self.filter_halfchannels_fee_base(1000, operator.ge))} half-channels have a base_fee >= 1000msat.")
        print(f" - {len(self.filter_halfchannels_fee_ppm(0))} half-channels have a ppm_fee of 0.")
        print(f" - {len(self.filter_halfchannels_fee_ppm(1000, operator.ge))} half-channels have a ppm_fee >= 1000.")
        print(f" - base_fee quantiles(10): {self.quantiles_halfchannels_fee_base(10)}.")
        print(f" - ppm_fee quantiles(10): {self.quantiles_halfchannels_fee_ppm(10)}.")
        print("")

        print("FEATURES")
        print(f" - {len(self.filter_nodes_feature_compulsory(LnFeatureBits.OPTION_DATA_LOSS_PROTECT))} nodes require data loss protection.")
        print(f" - {len(self.filter_nodes_feature(LnFeatureBits.GOSSIP_QUERIES))} nodes support gossip queries.")
        print(f" - {len(self.filter_nodes_feature(LnFeatureBits.GOSSIP_QUERIES_EX))} nodes support extended gossip queries.")
        print(f" - {len(self.filter_nodes_feature(LnFeatureBits.BASIC_MPP))} nodes support basic MPP.")
        print(f" - {len(self.filter_nodes_feature(LnFeatureBits.OPTION_ANCHOR_OUTPUTS))} nodes support anchor outputs.")
        print(f" - {len(self.filter_nodes_feature(LnFeatureBits.OPTION_SCID_ALIAS))} nodes support scid alias.")
        print(f" - {len(self.filter_nodes_feature(LnFeatureBits.OPTION_ZEROCONF))} nodes support zeroconf.")
        print("")

        print("#### pyln-client gossmap  END  ####")
