from pyln.testing.utils import TEST_NETWORK, TIMEOUT, VALGRIND, DEPRECATED_APIS  # noqa: F401
from pyln.testing.utils import env, only_one, wait_for, write_config, TailableProc, sync_blockheight, wait_channel_quiescent, get_tx_p2wsh_outnum, mine_funding_to_announce, scid_to_int  # noqa: F401
import bitstring
from pyln.client import Millisatoshi
from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND, EXPERIMENTAL_SPLICING
from pyln.proto.onion import TlvPayload
import struct
import subprocess
import tempfile
import time

COMPAT = env("COMPAT", "1") == "1"

# Big enough to make channels with 10k effective capacity, including Elements channels
# which have bigger txns
CHANNEL_SIZE = 50000


def default_ln_port(network: str) -> int:
    network_map = {
        "bitcoin": 9735,
        "testnet": 19735,
        "regtest": 19846,
        "signet": 39735,
        "liquid-regtest": 20735,
        "liquid": 9735,
        "testnet4": 49735,
    }
    return network_map[network]


def hex_bits(features):
    # We always to full bytes
    flen = (max(features + [0]) + 7) // 8 * 8
    res = bitstring.BitArray(length=flen)
    # Big endian sucketh.
    for f in features:
        res[flen - 1 - f] = 1
    return res.hex


def expected_peer_features(extra=[]):
    """Return the expected peer features hexstring for this configuration"""
    features = [0, 5, 7, 8, 11, 12, 14, 17, 19, 25, 27, 35, 39, 45, 47, 51]
    if EXPERIMENTAL_DUAL_FUND:
        # option_dual_fund
        features += [29]
    if EXPERIMENTAL_SPLICING:
        features += [63]  # option_splice
    if TEST_NETWORK != 'liquid-regtest':
        # Anchors, except for elements
        features += [23]
    return hex_bits(features + extra)


# With the addition of the keysend plugin, we now send a different set of
# features for the 'node' and the 'peer' feature sets
def expected_node_features(extra=[]):
    """Return the expected node features hexstring for this configuration"""
    features = [0, 5, 7, 8, 11, 12, 14, 17, 19, 25, 27, 35, 39, 45, 47, 51, 55]
    if EXPERIMENTAL_DUAL_FUND:
        # option_dual_fund
        features += [29]
    if EXPERIMENTAL_SPLICING:
        features += [63]  # option_splice
    if TEST_NETWORK != 'liquid-regtest':
        # Anchors, except for elements
        features += [23]
    return hex_bits(features + extra)


def expected_channel_features(extra=[]):
    """Return the expected channel features hexstring for this configuration"""
    features = []
    return hex_bits(features + extra)


def bkpr_account_balance(node, acct_id):
    balances = node.rpc.bkpr_listbalances()['accounts']
    acct = only_one([acct for acct in balances if acct['account'] == acct_id])
    return only_one(acct['balances'])['balance_msat']


def move_matches(exp, mv):
    if mv['type'] != exp['type']:
        return False
    if Millisatoshi(mv['credit_msat']) != Millisatoshi(exp['credit_msat']):
        return False
    if Millisatoshi(mv['debit_msat']) != Millisatoshi(exp['debit_msat']):
        return False
    if mv['tags'] != exp['tags']:
        return False
    if 'fees_msat' in exp:
        if 'fees_msat' not in mv:
            return False
        if Millisatoshi(mv['fees_msat']) != Millisatoshi(exp['fees_msat']):
            return False
    elif 'fees_msat' in mv:
        return False
    return True


def calc_lease_fee(amt, feerate, rates):
    fee = rates['lease_fee_base_msat']
    fee += amt * rates['lease_fee_basis'] // 10
    fee += rates['funding_weight'] * feerate
    return fee


def _dictify(balances):
    return {b['account_id']: Millisatoshi(b['balance_msat']) for b in balances['accounts']}


def check_balance_snaps(n, expected_bals):
    snaps = n.rpc.listsnapshots()['balance_snapshots']
    for snap, exp in zip(snaps, expected_bals):
        if snap['blockheight'] != exp['blockheight']:
            raise Exception('Unexpected balance snap blockheight: {} vs {}'.format(_dictify(snap), _dictify(exp)))
        if _dictify(snap) != _dictify(exp):
            raise Exception('Unexpected balance snap: {} vs {}'.format(_dictify(snap), _dictify(exp)))


def check_coin_moves(n, account_id, expected_moves, chainparams):
    moves = n.rpc.call('listcoinmoves_plugin')['coin_moves']
    # moves can lag; wait for a few seconds if we don't have correct number.
    # then move on: we'll get details below.
    expected_count = 0
    for m in enumerate(expected_moves):
        if isinstance(m, list):
            expected_count += len(m)
        else:
            expected_count += 1

    if len(moves) != expected_count:
        time.sleep(5)
        moves = n.rpc.call('listcoinmoves_plugin')['coin_moves']

    node_id = n.info['id']
    acct_moves = [m for m in moves if m['account_id'] == account_id]
    # Stash moves for errors, if needed
    _acct_moves = acct_moves
    for mv in acct_moves:
        print("{{'type': '{}', 'credit_msat': {}, 'debit_msat': {}, 'tags': '{}' , ['fees_msat'?: '{}']}},"
              .format(mv['type'],
                      Millisatoshi(mv['credit_msat']).millisatoshis,
                      Millisatoshi(mv['debit_msat']).millisatoshis,
                      mv['tags'],
                      mv['fees_msat'] if 'fees_msat' in mv else ''))
        if mv['version'] != 2:
            raise ValueError(f'version not 2 {mv}')
        if mv['node_id'] != node_id:
            raise ValueError(f'node_id not: {mv}')
        if mv['timestamp'] <= 0:
            raise ValueError(f'timestamp invalid: {mv}')
        if mv['coin_type'] != chainparams['bip173_prefix']:
            raise ValueError(f'coin_type not {chainparams["bip173_prefix"]}: {mv}')
        # chain moves should have blockheights
        if mv['type'] == 'chain_mvt' and mv['account_id'] != 'external' and 'blockheight' not in mv:
            raise ValueError(f'blockheight not set: {mv}')

    for num, m in enumerate(expected_moves):
        # They can group things which are in any order.
        if isinstance(m, list):
            number_moves = len(m)
            for acct_move in acct_moves[:number_moves]:
                found = None
                for i in range(len(m)):
                    if move_matches(m[i], acct_move):
                        found = i
                        break
                if found is None:
                    raise ValueError("Unexpected move {} amongst {}".format(acct_move, m))
                del m[i]
            acct_moves = acct_moves[number_moves:]
        else:
            if not move_matches(m, acct_moves[0]):
                raise ValueError("Unexpected move {}: {} != {}".format(num, acct_moves[0], m))
            acct_moves = acct_moves[1:]

    if acct_moves != []:
        raise ValueError(f'check_coin_moves failed: still has acct_moves {acct_moves}. exp: {expected_moves}. actual: {_acct_moves}')


def account_balance(n, account_id):
    moves = dedupe_moves(n.rpc.call('listcoinmoves_plugin')['coin_moves'])
    chan_moves = [m for m in moves if m['account_id'] == account_id]
    if len(chan_moves) == 0:
        raise ValueError(f"No channel moves found for {account_id}. {moves}")
    m_sum = Millisatoshi(0)
    for m in chan_moves:
        m_sum += Millisatoshi(m['credit_msat'])
        m_sum -= Millisatoshi(m['debit_msat'])
    return m_sum


def extract_utxos(moves):
    utxos = {}
    for m in moves:
        if 'utxo_txid' not in m:
            continue
        txid = m['utxo_txid']
        if txid not in utxos:
            utxos[txid] = []

        if 'txid' not in m:
            utxos[txid].append([m, None])
        else:
            evs = utxos[txid]
            # it's a withdrawal, find the deposit and add to the pair
            for ev in evs:
                if ev[0]['vout'] == m['vout']:
                    ev[1] = m
                    if ev[0]['output_msat'] != m['output_msat']:
                        raise ValueError(f'output_msat does not match. expected {ev[0]}. actual {m}')
                    break
    return utxos


def print_utxos(utxos):
    for k, us in utxos.items():
        print(k)
        for u in us:
            if u[1]:
                print('\t', u[0]['account_id'], u[0]['tags'], u[1]['tags'], u[1]['txid'])
            else:
                print('\t', u[0]['account_id'], u[0]['tags'], None, None)


def utxos_for_channel(utxoset, channel_id):
    relevant_txids = []
    chan_utxos = {}

    def _add_relevant(txid, utxo):
        if txid not in chan_utxos:
            chan_utxos[txid] = []
        chan_utxos[txid].append(utxo)

    for txid, utxo_list in utxoset.items():
        for utxo in utxo_list:
            if utxo[0]['account_id'] == channel_id:
                _add_relevant(txid, utxo)
                relevant_txids.append(txid)
                if utxo[1]:
                    relevant_txids.append(utxo[1]['txid'])
            elif txid in relevant_txids:
                _add_relevant(txid, utxo)
                if utxo[1]:
                    relevant_txids.append(utxo[1]['txid'])

    # if they're not well ordered, we'll leave some txids out
    for txid in relevant_txids:
        if txid not in chan_utxos:
            chan_utxos[txid] = utxoset[txid]

    return chan_utxos


def matchup_events(u_set, evs, chans, tag_list):
    if len(u_set) != len(evs):
        raise ValueError(f"utxo-set does not match expected (diff lens). exp {evs}, actual {u_set}")
    if len(u_set) == 0:
        raise ValueError(f"utxo-set is empty. exp {evs}, actual {u_set}")

    txid = u_set[0][0]['utxo_txid']
    # Stash the set for logging at end, if error
    _u_set = u_set
    for ev in evs:
        found = False
        for u in u_set:
            # We use 'cid' as a placeholder for the channel id, since it's
            # dyanmic, but we need to sub it in. 'chans' is a list of cids,
            # which are mapped to `cid` tags' suffixes. eg. 'cid1' is the
            # first cid in the chans list
            if ev[0][:3] == 'cid':
                idx = int(ev[0][3:])
                acct = chans[idx - 1]
            else:
                acct = ev[0]

            if u[0]['account_id'] != acct or u[0]['tags'] != ev[1]:
                continue

            if ev[2] is None:
                if u[1] is not None:
                    raise ValueError(f"Expected unspent utxo. exp {ev}, actual {u}")
                found = True
                u_set.remove(u)
                break

            # ugly hack to annotate two possible futures for a utxo
            if type(ev[2]) is tuple:
                tag = u[1]['tags'] if u[1] else u[1]
                if tag not in [x[0] for x in ev[2]]:
                    raise ValueError(f"Unable to find {tag} in event set {ev}")
                if not u[1]:
                    found = True
                    u_set.remove(u)
                    break
                for x in ev[2]:
                    if x[0] == u[1]['tags'] and 'to_miner' not in u[1]['tags']:
                        # Save the 'spent to' txid in the tag-list
                        tag_list[x[1]] = u[1]['txid']
            else:
                if ev[2] != u[1]['tags']:
                    raise ValueError(f"tags dont' match. exp {ev}, actual ({u[1]}) full utxo info: {u}")
                # Save the 'spent to' txid in the tag-list
                if 'to_miner' not in u[1]['tags']:
                    tag_list[ev[3]] = u[1]['txid']

            found = True
            u_set.remove(u)

        if not found:
            raise ValueError(f"Unable to find expected event in utxos. exp {ev}, utxos {u_set}")

    # Verify we used them all up
    if len(u_set) != 0:
        raise ValueError(f"Too many utxo events. exp {ev}, actual {_u_set} (extra: {u_set})")

    return txid


def dedupe_moves(moves):
    move_set = {}
    deduped_moves = []
    for move in moves:
        # Dupes only pertain to onchain moves?
        if 'utxo_txid' not in move:
            deduped_moves.append(move)
            continue

        outpoint = '{}:{};{}'.format(move['utxo_txid'], move['vout'], move['txid'] if 'txid' in move else 'xx')
        if outpoint not in move_set:
            deduped_moves.append(move)
            move_set[outpoint] = move
    return deduped_moves


def inspect_check_actual(txids, channel_id, actual, exp):
    if len(actual['outputs']) != len(exp):
        raise ValueError(f"actual outputs != exp. exp: {exp}. actual: {actual['outputs']}")

    for e in exp:
        # find the event in actual that matches
        found = False
        for a in actual['outputs']:
            if e[0].startswith('cid'):
                if a['account'] != channel_id:
                    continue
            elif a['account'] != e[0]:
                continue

            if e[1][0] != a['output_tag']:
                continue
            if e[2]:
                if e[2][0] != a['spend_tag']:
                    raise ValueError(f'spend_tag mismatch. expected: {e}, actual {a}')
                txids.append((e[3], a['spending_txid']))
            elif 'spend_tag' in a:
                raise ValueError(f'{a} contains "spend_tag", expecting {e}')

            found = True
            break
        if not found:
            raise ValueError(f'Unable to find actual tx {a} in expected {exp}')

    return txids


def check_inspect_channel(n, channel_id, expected_txs):
    actual_txs = n.rpc.bkpr_inspect(channel_id)['txs']
    # Stash a copy in case we need to print on error/assert at end
    _actual_txs = actual_txs
    if len(actual_txs) != len(expected_txs.keys()):
        raise ValueError(f'count actual_txs != expected exp: {expected_txs}')
    # start at the top
    exp = list(expected_txs.values())[0]
    actual = actual_txs[0]

    txids = []

    exp_counter = 1
    inspect_check_actual(txids, channel_id, actual, exp)
    actual_txs.remove(actual)

    for (marker, txid) in txids:
        actual = None
        for a in actual_txs:
            if a['txid'] == txid:
                actual = a
                break
        if not actual:
            raise ValueError(f'No "actual" tx found, looking for {txid}. {actual_txs}')
        exp = expected_txs[marker]
        inspect_check_actual(txids, channel_id, actual, exp)

        # after we've inspected it, remove it
        actual_txs.remove(actual)
        exp_counter += 1

    # Did we inspect everything?
    if len(actual_txs) != 0:
        raise ValueError(f'Had more txs than expected. expected: {expected_txs}. actual: {_actual_txs}')
    if exp_counter != len(expected_txs.keys()):
        raise ValueError(f'Had less txs than expected. expected: {expected_txs}. actual txs: {_actual_txs}')


def check_utxos_channel(n, chans, expected, exp_tag_list=None, filter_channel=None):
    tag_list = {}
    moves = n.rpc.call('listcoinmoves_plugin')['coin_moves']

    utxos = extract_utxos(dedupe_moves(moves))

    if filter_channel:
        utxos = utxos_for_channel(utxos, filter_channel)

    # Stash for errors, if we get them
    _utxos = utxos
    for tag, evs in expected.items():
        if tag not in tag_list:
            u_set = list(utxos.values())[0]
        elif tag in tag_list:
            u_set = utxos[tag_list[tag]]

        txid = matchup_events(u_set, evs, chans, tag_list)

        if tag not in tag_list:
            tag_list[tag] = txid

        # Remove checked set from utxos
        del utxos[txid]

    # Verify that we went through all of the utxos
    if len(utxos) != 0:
        raise ValueError(f"leftover utxos? expected: {expected}, actual: {_utxos}")

    # Verify that the expected tags match the found tags
    if exp_tag_list:
        for tag, txid in tag_list.items():
            if tag in exp_tag_list:
                if exp_tag_list[tag] != txid:
                    raise ValueError(f"expected tags txid {exp_tag_list[tag]} != actual {txid}. expected: {exp_tag_list}, actual: {tag_list}")

    return tag_list


def first_channel_id(n1, n2):
    return only_one(n1.rpc.listpeerchannels(n2.info['id'])['channels'])['channel_id']


def first_scid(n1, n2):
    return only_one(n1.rpc.listpeerchannels(n2.info['id'])['channels'])['short_channel_id']


def basic_fee(feerate, anchor_expected):
    if anchor_expected:
        # option_anchor_outputs / option_anchors_zero_fee_htlc_tx
        weight = 1124
    else:
        weight = 724
    return (weight * feerate) // 1000


def closing_fee(feerate, num_outputs):
    assert num_outputs == 1 or num_outputs == 2
    # Assumes p2tr outputs
    weight = 428 + (8 + 1 + 1 + 1 + 32) * 4 * num_outputs
    return (weight * feerate) // 1000


def scriptpubkey_addr(scriptpubkey):
    if 'addresses' in scriptpubkey:
        return scriptpubkey['addresses'][0]
    elif 'address' in scriptpubkey:
        # Modern bitcoin (at least, git master)
        return scriptpubkey['address']
    return None


class GenChannel(object):
    class Half(object):
        def __init__(self, enabled=True, htlc_min=0, htlc_max=None, basefee=0, propfee=1, delay=6):
            self.enabled = enabled
            self.htlc_min = htlc_min
            self.htlc_max = htlc_max
            self.basefee = basefee
            self.propfee = propfee
            self.delay = delay

    def __init__(self, node1, node2, capacity_sats=1000000, forward=None, reverse=None):
        """We fill in htlc_max on half to == capacity, if not set"""
        self.node1 = node1
        self.node2 = node2
        if forward is None:
            forward = GenChannel.Half()
        if reverse is None:
            reverse = GenChannel.Half()
        if forward.htlc_max is None:
            forward.htlc_max = capacity_sats * 1000
        if reverse.htlc_max is None:
            reverse.htlc_max = capacity_sats * 1000
        self.capacity_sats = capacity_sats
        self.half = [forward, reverse]


def generate_gossip_store(channels, nodemap={}):
    """Returns a gossip store file with the given channels in it, and a map of node labels -> ids
    """
    nodes = []

    def write_bignum(outf, val):
        if val < 253:
            outf.write(val.to_bytes(1, byteorder='big'))
        elif val <= 0xFFFF:
            outf.write(b'\xFD')
            outf.write(val.to_bytes(2, byteorder='big'))
        elif val <= 0xFFFFFFFF:
            outf.write(b'\xFE')
            outf.write(val.to_bytes(4, byteorder='big'))
        else:
            outf.write(b'\xFF')
            outf.write(val.to_bytes(8, byteorder='big'))

    def write_dumb_template(outf, channels, propname, illegalvals=[]):
        """We don't bother uniquifing, just one entry per chan dir"""
        # Template is simply all the values
        write_bignum(outf, len(channels) * 2)
        for c in channels:
            for d in (0, 1):
                v = getattr(c.half[d], propname)
                assert v not in illegalvals
                write_bignum(outf, v)

        # Now each entry for each channel half points into the values.
        for i in range(0, len(channels) * 2):
            write_bignum(outf, i)

    # First create nodes
    for c in channels:
        if c.node1 not in nodes:
            nodes.append(c.node1)
        if c.node2 not in nodes:
            nodes.append(c.node2)

    cfile = tempfile.NamedTemporaryFile(prefix='gs-compressed-')
    # <HEADER> := "GOSSMAP_COMPRESSv1\0"
    cfile.write(b'GOSSMAP_COMPRESSv1\x00')
    # <CHANNEL_ENDS> := {channel_count} {start_nodeidx}*{channel_count} {end_nodeidx}*{channel_count}
    write_bignum(cfile, len(channels))
    for c in channels:
        write_bignum(cfile, nodes.index(c.node1))
    for c in channels:
        write_bignum(cfile, nodes.index(c.node2))

    # <DISABLEDS> := <DISABLED>* {channel_count*2}
    # <DISABLED> := {chanidx}*2+{direction}
    for i, c in enumerate(channels):
        for d in (0, 1):
            if not c.half[d].enabled:
                write_bignum(cfile, i * 2 + d)
    write_bignum(cfile, len(channels) * 2)

    # <CAPACITIES> := <CAPACITY_TEMPLATES> {channel_count}*{capacity_idx}
    # <CAPACITY_TEMPLATES> := {capacity_count} {channel_count}*{capacity}
    max_htlc_defaults = []
    write_bignum(cfile, len(channels))
    for c in channels:
        write_bignum(cfile, c.capacity_sats)
        max_htlc_defaults.append(c.capacity_sats)
        max_htlc_defaults.append(c.capacity_sats)

    for i, _ in enumerate(channels):
        write_bignum(cfile, i)

    # <HTLC_MINS> := <HTLC_MIN_TEMPLATES> {channel_ count*2}*{htlc_min_idx}
    # <HTLC_MIN_TEMPLATES> := {htlc_min_count} {htlc_min_count}*{htlc_min}
    write_dumb_template(cfile, channels, 'htlc_min')
    # <HTLC_MAXS> := <HTLC_MAX_TEMPLATES> {channel_count*2}*{htlc_max_idx}
    # <HTLC_MAX_TEMPLATES> := {htlc_max_count} {htlc_max_count}*{htlc_max}
    # 0 and 1 have special meanings, don't use them!
    write_dumb_template(cfile, channels, 'htlc_max', [0, 1])
    # <BASEFEES> := <BASEFEE_TEMPLATES> {channel_count*2}*{basefee_idx}
    # <BASEFEE_TEMPLATES> := {basefee_count} {basefee_count}*{basefee}
    write_dumb_template(cfile, channels, 'basefee')
    # <PROPFEES> := <PROPFEE_TEMPLATES> {channel_count*2}*{propfee_idx}
    # <PROPFEE_TEMPLATES> := {propfee_count} {propfee_count}*{propfee}
    write_dumb_template(cfile, channels, 'propfee')
    # <DELAYS> := <DELAY_TEMPLATES> {channel_count*2}*{delay_idx}
    # <DELAY_TEMPLATES> := {delay_count} {delay_count}*{delay}
    write_dumb_template(cfile, channels, 'delay')

    cfile.flush()

    outfile = tempfile.NamedTemporaryFile(prefix='gossip-store-')
    nodeids = subprocess.check_output(['devtools/gossmap-compress']
                                      + [f'--node-map={num}={nodeid}' for num, nodeid in nodemap.items()]
                                      + ['decompress',
                                         cfile.name,
                                         outfile.name]).decode('utf-8').splitlines()
    cfile.close()

    # Create map of their node names to the ids.
    nodemap = {}
    for i, n in enumerate(nodeids):
        nodemap[nodes[i]] = n

    return outfile, nodemap


def tu64_encode(i: int):
    """Encode a tu64 (or tu32 etc) value"""
    ret = struct.pack("!Q", i)
    while ret.startswith(b'\0'):
        ret = ret[1:]
    return ret


def serialize_payload_tlv(amount_msat, delay, next_channel, blockheight):
    """Encode TLV onion payload for non-final hops, returns bytes"""
    block, tx, out = next_channel.split('x')

    payload = TlvPayload()
    # BOLT #4:
    #     1. type: 2 (`amt_to_forward`)
    #     2. data:
    #         * [`tu64`:`amt_to_forward`]
    payload.add_field(2, tu64_encode(int(amount_msat)))
    # BOLT #4:
    #    1. type: 4 (`outgoing_cltv_value`)
    #    2. data:
    #        * [`tu32`:`outgoing_cltv_value`]
    payload.add_field(4, tu64_encode(blockheight + delay))
    # BOLT #4:
    #    1. type: 6 (`short_channel_id`)
    #    2. data:
    #        * [`short_channel_id`:`short_channel_id`]
    payload.add_field(6, struct.pack("!Q", int(block) << 40 | int(tx) << 16 | int(out)))
    return payload.to_bytes()


def serialize_payload_final_tlv(amount_msat, delay, total_msat, blockheight, payment_secret: str):
    """Encode TLV onion payload for final hop, returns bytes"""
    payload = TlvPayload()
    # BOLT #4:
    #     1. type: 2 (`amt_to_forward`)
    #     2. data:
    #         * [`tu64`:`amt_to_forward`]
    payload.add_field(2, tu64_encode(int(amount_msat)))
    # BOLT #4:
    #    1. type: 4 (`outgoing_cltv_value`)
    #    2. data:
    #        * [`tu32`:`outgoing_cltv_value`]
    payload.add_field(4, tu64_encode(blockheight + delay))
    # BOLT #4:
    #    1. type: 8 (`payment_data`)
    #    2. data:
    #        * [`32*byte`:`payment_secret`]
    #        * [`tu64`:`total_msat`]
    payload.add_field(8, bytes.fromhex(payment_secret) + tu64_encode(int(total_msat)))
    return payload.to_bytes()
