from pyln.testing.utils import TEST_NETWORK, SLOW_MACHINE, TIMEOUT, VALGRIND, DEVELOPER, DEPRECATED_APIS  # noqa: F401
from pyln.testing.utils import env, only_one, wait_for, write_config, TailableProc, sync_blockheight, wait_channel_quiescent, get_tx_p2wsh_outnum  # noqa: F401


EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"
COMPAT = env("COMPAT", "1") == "1"


def expected_peer_features():
    """Return the expected peer features hexstring for this configuration"""
    # features 1, 3, 7, 9, 11, 13, 15 and 17 (0x02aaa2).
    return "02aaa2"


# With the addition of the keysend plugin, we now send a different set of
# features for the 'node' and the 'peer' feature sets
def expected_node_features():
    """Return the expected node features hexstring for this configuration"""
    # features 1, 3, 7, 9, 11, 13, 15, 17 and 55 (0x8000000002aaa2).
    return "8000000002aaa2"


def expected_channel_features():
    """Return the expected channel features hexstring for this configuration"""
    # experimental OPT_ONION_MESSAGES
    if EXPERIMENTAL_FEATURES:
        return '80000000000000000000000000'
    else:
        return ''


def check_coin_moves(n, account_id, expected_moves):
    moves = n.rpc.call('listcoinmoves_plugin')['coin_moves']
    node_id = n.info['id']
    acct_moves = [m for m in moves if m['account_id'] == account_id]
    assert len(acct_moves) == len(expected_moves)
    for mv, exp in list(zip(acct_moves, expected_moves)):
        assert mv['version'] == 1
        assert mv['node_id'] == node_id
        assert mv['type'] == exp['type']
        assert mv['credit'] == "{}msat".format(exp['credit'])
        assert mv['debit'] == "{}msat".format(exp['debit'])
        assert mv['tag'] == exp['tag']
        assert mv['timestamp'] > 0
        assert mv['unit_of_account'] == 'btc'
        # chain moves should have blockheights
        if mv['type'] == 'chain_mvt':
            assert mv['blockheight'] is not None


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
