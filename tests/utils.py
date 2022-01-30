from pyln.testing.utils import TEST_NETWORK, TIMEOUT, VALGRIND, DEVELOPER, DEPRECATED_APIS  # noqa: F401
from pyln.testing.utils import env, only_one, wait_for, write_config, TailableProc, sync_blockheight, wait_channel_quiescent, get_tx_p2wsh_outnum, mine_funding_to_announce  # noqa: F401
import bitstring
from pyln.client import Millisatoshi
from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND
import time

EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"
COMPAT = env("COMPAT", "1") == "1"


def anchor_expected():
    return EXPERIMENTAL_FEATURES or EXPERIMENTAL_DUAL_FUND


def hex_bits(features):
    # We always to full bytes
    flen = (max(features + [0]) + 7) // 8 * 8
    res = bitstring.BitArray(length=flen)
    # Big endian sucketh.
    for f in features:
        res[flen - 1 - f] = 1
    return res.hex


def expected_peer_features(wumbo_channels=False, extra=[]):
    """Return the expected peer features hexstring for this configuration"""
    features = [1, 5, 7, 9, 11, 13, 14, 17, 27]
    if EXPERIMENTAL_FEATURES:
        # OPT_ONION_MESSAGES
        features += [39]
        # option_anchor_outputs
        features += [21]
        # option_quiesce
        features += [35]
    if wumbo_channels:
        features += [19]
    if EXPERIMENTAL_DUAL_FUND:
        # option_anchor_outputs
        features += [21]
        # option_dual_fund
        features += [29]
    return hex_bits(features + extra)


# With the addition of the keysend plugin, we now send a different set of
# features for the 'node' and the 'peer' feature sets
def expected_node_features(wumbo_channels=False, extra=[]):
    """Return the expected node features hexstring for this configuration"""
    features = [1, 5, 7, 9, 11, 13, 14, 17, 27, 55]
    if EXPERIMENTAL_FEATURES:
        # OPT_ONION_MESSAGES
        features += [39]
        # option_anchor_outputs
        features += [21]
        # option_quiesce
        features += [35]
    if wumbo_channels:
        features += [19]
    if EXPERIMENTAL_DUAL_FUND:
        # option_anchor_outputs
        features += [21]
        # option_dual_fund
        features += [29]
    return hex_bits(features + extra)


def expected_channel_features(wumbo_channels=False, extra=[]):
    """Return the expected channel features hexstring for this configuration"""
    features = []
    return hex_bits(features + extra)


def move_matches(exp, mv):
    if mv['type'] != exp['type']:
        return False
    if mv['credit'] != "{}msat".format(exp['credit']):
        return False
    if mv['debit'] != "{}msat".format(exp['debit']):
        return False
    if mv['tags'] != exp['tags']:
        return False
    if 'fees' in exp:
        if 'fees' not in mv:
            return False
        if mv['fees'] != exp['fees']:
            return False
    elif 'fees' in mv:
        return False
    return True


def calc_lease_fee(amt, feerate, rates):
    fee = rates['lease_fee_base_msat']
    fee += amt * rates['lease_fee_basis'] // 10
    fee += rates['funding_weight'] * feerate
    return fee


def check_balance_snaps(n, expected_bals):
    snaps = n.rpc.listsnapshots()['balance_snapshots']
    for snap, exp in zip(snaps, expected_bals):
        assert snap['blockheight'] == exp['blockheight']
        for acct, exp_acct in zip(snap['accounts'], exp['accounts']):
            # FIXME: also check 'account_id's (these change every run)
            for item in ['balance']:
                assert acct[item] == exp_acct[item]


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
    for mv in acct_moves:
        print("{{'type': '{}', 'credit': {}, 'debit': {}, 'tags': '{}' , ['fees'?: '{}']}},"
              .format(mv['type'],
                      Millisatoshi(mv['credit']).millisatoshis,
                      Millisatoshi(mv['debit']).millisatoshis,
                      mv['tags'],
                      mv['fees'] if 'fees' in mv else ''))
        assert mv['version'] == 2
        assert mv['node_id'] == node_id
        assert mv['timestamp'] > 0
        assert mv['coin_type'] == chainparams['bip173_prefix']
        # chain moves should have blockheights
        if mv['type'] == 'chain_mvt' and mv['account_id'] != 'external':
            assert mv['blockheight'] is not None

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

    assert acct_moves == []


def account_balance(n, account_id):
    moves = dedupe_moves(n.rpc.call('listcoinmoves_plugin')['coin_moves'])
    chan_moves = [m for m in moves if m['account_id'] == account_id]
    assert len(chan_moves) > 0
    m_sum = 0
    for m in chan_moves:
        m_sum += int(m['credit'][:-4])
        m_sum -= int(m['debit'][:-4])
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
                    assert ev[0]['output_value'] == m['output_value']
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
    assert len(u_set) == len(evs) and len(u_set) > 0

    txid = u_set[0][0]['utxo_txid']
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
                assert u[1] is None
                found = True
                u_set.remove(u)
                break

            # ugly hack to annotate two possible futures for a utxo
            if type(ev[2]) is tuple:
                tag = u[1]['tags'] if u[1] else u[1]
                assert tag in [x[0] for x in ev[2]]
                if not u[1]:
                    found = True
                    u_set.remove(u)
                    break
                for x in ev[2]:
                    if x[0] == u[1]['tags'] and 'to_miner' not in u[1]['tags']:
                        # Save the 'spent to' txid in the tag-list
                        tag_list[x[1]] = u[1]['txid']
            else:
                assert ev[2] == u[1]['tags']
                # Save the 'spent to' txid in the tag-list
                if 'to_miner' not in u[1]['tags']:
                    tag_list[ev[3]] = u[1]['txid']

            found = True
            u_set.remove(u)

        assert found

    # Verify we used them all up
    assert len(u_set) == 0
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


def check_utxos_channel(n, chans, expected, exp_tag_list=None, filter_channel=None):
    tag_list = {}
    moves = n.rpc.call('listcoinmoves_plugin')['coin_moves']

    utxos = extract_utxos(dedupe_moves(moves))

    if filter_channel:
        utxos = utxos_for_channel(utxos, filter_channel)

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
    assert len(utxos) == 0

    # Verify that the expected tags match the found tags
    if exp_tag_list:
        for tag, txid in tag_list.items():
            if tag in exp_tag_list:
                assert exp_tag_list[tag] == txid

    return tag_list


def first_channel_id(n1, n2):
    return only_one(only_one(n1.rpc.listpeers(n2.info['id'])['peers'])['channels'])['channel_id']


def basic_fee(feerate):
    if EXPERIMENTAL_FEATURES or EXPERIMENTAL_DUAL_FUND:
        # option_anchor_outputs
        weight = 1124
    else:
        weight = 724
    return (weight * feerate) // 1000


def closing_fee(feerate, num_outputs):
    assert num_outputs == 1 or num_outputs == 2
    weight = 424 + 124 * num_outputs
    return (weight * feerate) // 1000


def scriptpubkey_addr(scriptpubkey):
    if 'addresses' in scriptpubkey:
        return scriptpubkey['addresses'][0]
    elif 'address' in scriptpubkey:
        # Modern bitcoin (at least, git master)
        return scriptpubkey['address']
    return None
