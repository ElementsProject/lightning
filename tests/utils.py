from pyln.testing.utils import TEST_NETWORK, TIMEOUT, VALGRIND, DEVELOPER, DEPRECATED_APIS  # noqa: F401
from pyln.testing.utils import env, only_one, wait_for, write_config, TailableProc, sync_blockheight, wait_channel_quiescent, get_tx_p2wsh_outnum  # noqa: F401
import bitstring
from pyln.client import Millisatoshi
from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND

EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"
COMPAT = env("COMPAT", "1") == "1"


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
    features = [1, 5, 7, 9, 11, 13, 15, 17, 27]
    if EXPERIMENTAL_FEATURES:
        # OPT_ONION_MESSAGES
        features += [103]
        # option_anchor_outputs
        features += [21]
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
    features = [1, 5, 7, 9, 11, 13, 15, 17, 27, 55]
    if EXPERIMENTAL_FEATURES:
        # OPT_ONION_MESSAGES
        features += [103]
        # option_anchor_outputs
        features += [21]
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
    if mv['tag'] != exp['tag']:
        return False
    return True


def check_coin_moves(n, account_id, expected_moves, chainparams):
    moves = n.rpc.call('listcoinmoves_plugin')['coin_moves']
    node_id = n.info['id']
    acct_moves = [m for m in moves if m['account_id'] == account_id]
    for mv in acct_moves:
        print("{{'type': '{}', 'credit': {}, 'debit': {}, 'tag': '{}'}},"
              .format(mv['type'],
                      Millisatoshi(mv['credit']).millisatoshis,
                      Millisatoshi(mv['debit']).millisatoshis,
                      mv['tag']))
        assert mv['version'] == 1
        assert mv['node_id'] == node_id
        assert mv['timestamp'] > 0
        assert mv['coin_type'] == chainparams['bip173_prefix']
        # chain moves should have blockheights
        if mv['type'] == 'chain_mvt':
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


def check_coin_moves_idx(n):
    """ Just check that the counter increments smoothly"""
    moves = n.rpc.call('listcoinmoves_plugin')['coin_moves']
    idx = 0
    for m in moves:
        c_idx = m['movement_idx']
        # verify that the index count increments smoothly here, also
        if c_idx == 0 and idx == 0:
            continue
        assert c_idx == idx + 1
        idx = c_idx


def account_balance(n, account_id):
    moves = n.rpc.call('listcoinmoves_plugin')['coin_moves']
    chan_moves = [m for m in moves if m['account_id'] == account_id]
    assert len(chan_moves) > 0
    m_sum = 0
    for m in chan_moves:
        m_sum += int(m['credit'][:-4])
        m_sum -= int(m['debit'][:-4])
    return m_sum


def first_channel_id(n1, n2):
    return only_one(only_one(n1.rpc.listpeers(n2.info['id'])['peers'])['channels'])['channel_id']


def basic_fee(feerate):
    if EXPERIMENTAL_FEATURES or EXPERIMENTAL_DUAL_FUND:
        # option_anchor_outputs
        weight = 1124
    else:
        weight = 724
    return (weight * feerate) // 1000


def scriptpubkey_addr(scriptpubkey):
    if 'addresses' in scriptpubkey:
        return scriptpubkey['addresses'][0]
    elif 'address' in scriptpubkey:
        # Modern bitcoin (at least, git master)
        return scriptpubkey['address']
    return None
