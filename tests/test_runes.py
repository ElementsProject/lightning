from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
import base64
import os
import pytest
import time
import unittest


def test_createrune(node_factory):
    l1 = node_factory.get_node()

    # l1's master rune secret is edb8893c04fdeef8f5f06ed70edef309a5c83f20624594e136e392504a270c40
    rune1 = l1.rpc.createrune()
    assert rune1['rune'] == 'OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA=='
    assert rune1['unique_id'] == '0'
    rune2 = l1.rpc.createrune(restrictions="readonly")
    assert rune2['rune'] == 'zm0x_eLgHexaTvZn3Cz7gb_YlvrlYGDo_w4BYlR9SS09MSZtZXRob2RebGlzdHxtZXRob2ReZ2V0fG1ldGhvZD1zdW1tYXJ5Jm1ldGhvZC9saXN0ZGF0YXN0b3Jl'
    assert rune2['unique_id'] == '1'
    rune3 = l1.rpc.createrune(restrictions=[["time>1656675211"]])
    assert rune3['rune'] == 'mxHwVsC_W-PH7r79wXQWqxBNHaHncIqIjEPyP_vGOsE9MiZ0aW1lPjE2NTY2NzUyMTE='
    assert rune3['unique_id'] == '2'
    rune4 = l1.rpc.createrune(restrictions=[["id^022d223620a359a47ff7"], ["method=listpeers"]])
    assert rune4['rune'] == 'YPojv9qgHPa3im0eiqRb-g8aRq76OasyfltGGqdFUOU9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJz'
    assert rune4['unique_id'] == '3'
    rune5 = l1.rpc.commando_rune(rune4['rune'], [["pnamelevel!", "pnamelevel/io"]])
    assert rune5['rune'] == 'Zm7A2mKkLnd5l6Er_OMAHzGKba97ij8lA-MpNYMw9nk9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJzJnBuYW1lbGV2ZWwhfHBuYW1lbGV2ZWwvaW8='
    assert rune5['unique_id'] == '3'
    rune6 = l1.rpc.commando_rune(rune5['rune'], [["parr1!", "parr1/io"]])
    assert rune6['rune'] == 'm_tyR0qqHUuLEbFJW6AhmBg-9npxVX2yKocQBFi9cvY9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJzJnBuYW1lbGV2ZWwhfHBuYW1lbGV2ZWwvaW8mcGFycjEhfHBhcnIxL2lv'
    assert rune6['unique_id'] == '3'
    rune7 = l1.rpc.createrune(restrictions=[["pnum=0"]])
    assert rune7['rune'] == 'enX0sTpHB8y1ktyTAF80CnEvGetG340Ne3AGItudBS49NCZwbnVtPTA='
    assert rune7['unique_id'] == '4'
    rune8 = l1.rpc.createrune(rune7['rune'], [["rate=3"]])
    assert rune8['rune'] == '_h2eKjoK7ITAF-JQ1S5oum9oMQesrz-t1FR9kDChRB49NCZwbnVtPTAmcmF0ZT0z'
    assert rune8['unique_id'] == '4'
    rune9 = l1.rpc.createrune(rune8['rune'], [["rate=1"]])
    assert rune9['rune'] == 'U1GDXqXRvfN1A4WmDVETazU9YnvMsDyt7WwNzpY0khE9NCZwbnVtPTAmcmF0ZT0zJnJhdGU9MQ=='
    assert rune9['unique_id'] == '4'

    # Test rune with \|.
    weirdrune = l1.rpc.createrune(restrictions=[["method=invoice"],
                                                ["pnamedescription=@tipjar|jb55@sendsats.lol"]])

    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=weirdrune['rune'],
                         method='invoice',
                         params={"amount_msat": "any",
                                 "label": "lbl",
                                 "description": "@tipjar\\|jb55@sendsats.lol"})
    assert exc_info.value.error['code'] == 0x5de

    assert l1.rpc.checkrune(nodeid=l1.info['id'],
                            rune=weirdrune['rune'],
                            method='invoice',
                            params={"amount_msat": "any",
                                    "label": "lbl",
                                    "description": "@tipjar|jb55@sendsats.lol"})['valid'] is True

    runedecodes = ((rune1, []),
                   (rune2, [{'alternatives': ['method^list', 'method^get', 'method=summary'],
                             'summary': "method (of command) starts with 'list' OR method (of command) starts with 'get' OR method (of command) equal to 'summary'"},
                            {'alternatives': ['method/listdatastore'],
                             'summary': "method (of command) unequal to 'listdatastore'"}]),
                   (rune4, [{'alternatives': ['id^022d223620a359a47ff7'],
                             'summary': "id (of commanding peer) starts with '022d223620a359a47ff7'"},
                            {'alternatives': ['method=listpeers'],
                             'summary': "method (of command) equal to 'listpeers'"}]),
                   (rune5, [{'alternatives': ['id^022d223620a359a47ff7'],
                             'summary': "id (of commanding peer) starts with '022d223620a359a47ff7'"},
                            {'alternatives': ['method=listpeers'],
                             'summary': "method (of command) equal to 'listpeers'"},
                            {'alternatives': ['pnamelevel!', 'pnamelevel/io'],
                             'summary': "pnamelevel (object parameter 'level') is missing OR pnamelevel (object parameter 'level') unequal to 'io'"}]),
                   (rune6, [{'alternatives': ['id^022d223620a359a47ff7'],
                             'summary': "id (of commanding peer) starts with '022d223620a359a47ff7'"},
                            {'alternatives': ['method=listpeers'],
                             'summary': "method (of command) equal to 'listpeers'"},
                            {'alternatives': ['pnamelevel!', 'pnamelevel/io'],
                             'summary': "pnamelevel (object parameter 'level') is missing OR pnamelevel (object parameter 'level') unequal to 'io'"},
                            {'alternatives': ['parr1!', 'parr1/io'],
                             'summary': "parr1 (array parameter #1) is missing OR parr1 (array parameter #1) unequal to 'io'"}]),
                   (rune7, [{'alternatives': ['pnum=0'],
                             'summary': "pnum (number of command parameters) equal to 0"}]),
                   (rune8, [{'alternatives': ['pnum=0'],
                             'summary': "pnum (number of command parameters) equal to 0"},
                            {'alternatives': ['rate=3'],
                             'summary': "rate (max per minute) equal to 3"}]),
                   (rune9, [{'alternatives': ['pnum=0'],
                             'summary': "pnum (number of command parameters) equal to 0"},
                            {'alternatives': ['rate=3'],
                             'summary': "rate (max per minute) equal to 3"},
                            {'alternatives': ['rate=1'],
                             'summary': "rate (max per minute) equal to 1"}]))
    for decode in runedecodes:
        rune = decode[0]
        restrictions = decode[1]
        decoded = l1.rpc.decode(rune['rune'])
        assert decoded['type'] == 'rune'
        assert decoded['unique_id'] == rune['unique_id']
        assert decoded['valid'] is True
        assert decoded['restrictions'] == restrictions

    # Time handling is a bit special, since we annotate the timestamp with how far away it is.
    decoded = l1.rpc.decode(rune3['rune'])
    assert decoded['type'] == 'rune'
    assert decoded['unique_id'] == rune3['unique_id']
    assert decoded['valid'] is True
    assert len(decoded['restrictions']) == 1
    assert decoded['restrictions'][0]['alternatives'] == ['time>1656675211']
    assert decoded['restrictions'][0]['summary'].startswith("time (in seconds since 1970) greater than 1656675211 (")

    # Replace rune3 with a more useful timestamp!
    expiry = int(time.time()) + 15
    rune3 = l1.rpc.createrune(restrictions=[["time<{}".format(expiry)]])

    successes = ((rune1, "listpeers", {}),
                 (rune2, "listpeers", {}),
                 (rune2, "getinfo", {}),
                 (rune2, "getinfo", {}),
                 (rune3, "getinfo", {}),
                 (rune7, "listpeers", []),
                 (rune7, "getinfo", {}),
                 (rune9, "getinfo", {}),
                 (rune8, "getinfo", {}),
                 (rune8, "getinfo", {}))

    failures = ((rune2, "withdraw", {}),
                (rune2, "plugin", {'subcommand': 'list'}),
                (rune3, "getinfo", {}),
                (rune4, "listnodes", {}),
                (rune5, "listpeers", {'id': l1.info['id'], 'level': 'io'}),
                (rune6, "listpeers", [l1.info['id'], 'io']),
                (rune7, "listpeers", [l1.info['id']]),
                (rune7, "listpeers", {'id': l1.info['id']}))

    for rune, cmd, params in successes:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune['rune'],
                         method=cmd,
                         params=params)['valid'] is True

    while time.time() < expiry:
        time.sleep(1)

    for rune, cmd, params in failures:
        print("{} {}".format(cmd, params))
        with pytest.raises(RpcError, match='Not permitted:') as exc_info:
            l1.rpc.checkrune(nodeid=l1.info['id'],
                             rune=rune['rune'],
                             method=cmd,
                             params=params)
        assert exc_info.value.error['code'] == 0x5de

    # Now, this can flake if we cross a minute boundary!  So wait until
    # It succeeds again.
    while True:
        try:
            l1.rpc.checkrune(nodeid=l1.info['id'],
                             rune=rune8['rune'],
                             method='getinfo')
            break
        except RpcError as e:
            assert e.error['code'] == 0x5de
        time.sleep(1)

    # This fails immediately, since we've done one.
    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune9['rune'],
                         method='getinfo',
                         params={})
    assert exc_info.value.error['code'] == 0x5de

    # Two more succeed for rune8.
    for _ in range(2):
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune8['rune'],
                         method='getinfo',
                         params={})
    assert exc_info.value.error['code'] == 0x5de

    # Now we've had 3 in one minute, this will fail.
    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune8['rune'],
                         method='getinfo',
                         params={})
    assert exc_info.value.error['code'] == 0x5de

    # rune5 can only be used by l2:
    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune5['rune'],
                         method="listpeers",
                         params={})
    assert exc_info.value.error['code'] == 0x5de

    # Now wait for ratelimit expiry, ratelimits should reset.
    time.sleep(61)

    for rune, cmd, params in ((rune9, "getinfo", {}),
                              (rune8, "getinfo", {}),
                              (rune8, "getinfo", {})):
        assert l1.rpc.checkrune(nodeid=l1.info['id'],
                                rune=rune['rune'],
                                method=cmd,
                                params=params)['valid'] is True


def test_showrunes(node_factory):
    l1 = node_factory.get_node()
    rune1 = l1.rpc.createrune()
    assert rune1 == {
        'rune': 'OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA==',
        'unique_id': '0',
        'warning_unrestricted_rune': 'WARNING: This rune has no restrictions! Anyone who has access to this rune could drain funds from your node. Be careful when giving this to apps that you don\'t trust. Consider using the restrictions parameter to only allow access to specific rpc methods.'
    }
    showrunes = l1.rpc.showrunes()
    assert len(l1.rpc.showrunes()) == 1
    l1.rpc.createrune()
    showrunes = l1.rpc.showrunes()
    assert len(showrunes['runes']) == 2
    assert showrunes == {
        'runes': [
            {
                'rune': 'OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA==',
                'unique_id': '0',
                'restrictions': [],
                'restrictions_as_english': ''
            },
            {
                'rune': 'geZmO6U7yqpHn-moaX93FVMVWrDRfSNY4AXx9ypLcqg9MQ==',
                'unique_id': '1',
                'restrictions': [],
                'restrictions_as_english': ''
            }
        ]
    }

    our_unstored_rune = l1.rpc.showrunes(rune='lI6iPwM1R9OkcRW25SH0a06PscPDinTfLFAjzSGFGE09OQ==')['runes'][0]
    assert our_unstored_rune['unique_id'] == '9'
    assert our_unstored_rune['stored'] is False

    not_our_rune = l1.rpc.showrunes(rune='oNJAqigqDrHBGzsm7gV3z87oGpzq-KqFlOxx2O9iEQk9MA==')['runes'][0]
    assert not_our_rune['stored'] is False
    assert not_our_rune['our_rune'] is False


def test_blacklistrune(node_factory):
    l1 = node_factory.get_node()

    rune0 = l1.rpc.createrune()
    assert rune0['unique_id'] == '0'
    rune1 = l1.rpc.createrune()
    assert rune1['unique_id'] == '1'

    # Make sure runes work!
    assert l1.rpc.call(method='checkrune',
                       payload={'nodeid': l1.info['id'],
                                'rune': rune0['rune'],
                                'method': 'getinfo'})['valid'] is True

    assert l1.rpc.call(method='checkrune',
                       payload={'nodeid': l1.info['id'],
                                'rune': rune1['rune'],
                                'method': 'getinfo'})['valid'] is True

    blacklist = l1.rpc.blacklistrune(start=1)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 1}]}

    # Make sure rune id 1 does not work!
    with pytest.raises(RpcError, match='Not authorized: Blacklisted rune') as exc_info:
        l1.rpc.call(method='checkrune',
                    payload={'nodeid': l1.info['id'],
                             'rune': rune1['rune'],
                             'method': 'getinfo'})
    assert exc_info.value.error['code'] == 0x5df

    # But, other rune still works!
    assert l1.rpc.call(method='checkrune',
                       payload={'nodeid': l1.info['id'],
                                'rune': rune0['rune'],
                                'method': 'getinfo'})['valid'] is True

    blacklist = l1.rpc.blacklistrune(start=2)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 2}]}

    blacklist = l1.rpc.blacklistrune(start=6)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 2},
                                       {'start': 6, 'end': 6}]}

    blacklist = l1.rpc.blacklistrune(start=3, end=5)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 6}]}

    blacklist = l1.rpc.blacklistrune(start=9)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 6},
                                       {'start': 9, 'end': 9}]}

    blacklist = l1.rpc.blacklistrune(start=0)
    assert blacklist == {'blacklist': [{'start': 0, 'end': 6},
                                       {'start': 9, 'end': 9}]}

    # # Now both runes fail!
    with pytest.raises(RpcError, match='Not authorized: Blacklisted rune') as exc_info:
        l1.rpc.call(method='checkrune',
                    payload={'nodeid': l1.info['id'],
                             'rune': rune0['rune'],
                             'method': 'getinfo'})
    assert exc_info.value.error['code'] == 0x5df

    with pytest.raises(RpcError, match='Not authorized: Blacklisted rune') as exc_info:
        l1.rpc.call(method='checkrune',
                    payload={'nodeid': l1.info['id'],
                             'rune': rune1['rune'],
                             'method': 'getinfo'})
    assert exc_info.value.error['code'] == 0x5df

    blacklist = l1.rpc.blacklistrune()
    assert blacklist == {'blacklist': [{'start': 0, 'end': 6},
                                       {'start': 9, 'end': 9}]}

    blacklisted_rune = l1.rpc.showrunes(rune='geZmO6U7yqpHn-moaX93FVMVWrDRfSNY4AXx9ypLcqg9MQ==')['runes'][0]['blacklisted']
    assert blacklisted_rune is True


def test_badrune(node_factory):
    """Test invalid UTF-8 encodings in rune: used to make us kill the offers plugin which implements decode, as it gave bad utf8!"""
    l1 = node_factory.get_node()
    l1.rpc.decode('5zi6-ugA6hC4_XZ0R7snl5IuiQX4ugL4gm9BQKYaKUU9gCZtZXRob2RebGlzdHxtZXRob2ReZ2V0fG1ldGhvZD1zdW1tYXJ5Jm1ldGhvZC9saXN0ZGF0YXN0b3Jl')
    rune = l1.rpc.createrune(restrictions="readonly")

    binrune = base64.urlsafe_b64decode(rune['rune'])
    # Mangle each part, try decode. Skip most of the boring chars
    # (just '|', '&', '#').
    for i in range(32, len(binrune)):
        for span in (range(0, 32), (124, 38, 35), range(127, 256)):
            for c in span:
                modrune = binrune[:i] + bytes([c]) + binrune[i + 1:]
                try:
                    l1.rpc.decode(base64.urlsafe_b64encode(modrune).decode('utf8'))
                except RpcError:
                    pass


def test_checkrune(node_factory):
    l1 = node_factory.get_node()
    rune1 = l1.rpc.createrune()
    rune2 = l1.rpc.createrune(restrictions="readonly")

    res1 = l1.rpc.checkrune(nodeid=l1.info['id'],
                            rune=rune1['rune'],
                            method='invoice',
                            params={'amount_msat': '10000'})

    assert res1['valid'] is True

    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.call(method='checkrune',
                    payload={'nodeid': l1.info['id'],
                             'rune': rune2['rune'],
                             'method': 'invoice',
                             'params': {"amount_msat": "1000", "label": "lbl", "description": "tipjar"}})
    assert exc_info.value.error['code'] == 0x5de


def test_rune_pay_amount(node_factory):
    l1, l2 = node_factory.line_graph(2)

    # This doesn't really work, since amount_msat is illegal if invoice
    # includes an amount, and runes aren't smart enough to decode bolt11!
    rune = l1.rpc.createrune(restrictions=[['method=pay'],
                                           ['pnameamountmsat<10000']])['rune']

    inv1 = l2.rpc.invoice(amount_msat=12300, label='inv1', description='description1')['bolt11']
    inv2 = l2.rpc.invoice(amount_msat='any', label='inv2', description='description2')['bolt11']

    # Rune requires amount_msat < 10,000!
    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune,
                         method='pay',
                         params={'bolt11': inv1})
    assert exc_info.value.error['code'] == 0x5de

    # As a named parameter!
    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune,
                         method='pay',
                         params=[inv1])
    assert exc_info.value.error['code'] == 0x5de

    # Can't get around it this way!
    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune,
                         method='pay',
                         params=[inv2, 12000])
    assert exc_info.value.error['code'] == 0x5de

    # Nor this way, using a string!
    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune,
                         method='pay',
                         params={'bolt11': inv2, 'amount_msat': '10000sat'})
    assert exc_info.value.error['code'] == 0x5de

    # Too much!
    with pytest.raises(RpcError, match='Not permitted:') as exc_info:
        l1.rpc.checkrune(nodeid=l1.info['id'],
                         rune=rune,
                         method='pay',
                         params={'bolt11': inv2, 'amount_msat': 12000})
    assert exc_info.value.error['code'] == 0x5de

    # This works
    res = l1.rpc.checkrune(nodeid=l1.info['id'],
                           rune=rune,
                           method='pay',
                           params={'bolt11': inv2, 'amount_msat': 9999})
    assert res['valid'] is True


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Depends on canned sqlite3 db")
@unittest.skipIf(TEST_NETWORK != 'regtest', 'canned sqlite3 db is regtest')
def test_commando_rune_migration(node_factory):
    """Test migration from commando's datastore using db from test_commando_listrunes"""
    l1 = node_factory.get_node(dbfile='commando_listrunes.sqlite3.xz',
                               options={'database-upgrade': True})

    # This happens really early in logs!
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_logs(['Transferring commando rune to db: '] * 2)

    # datastore should be empty:
    assert l1.rpc.listdatastore(['commando']) == {'datastore': []}

    # Should match commando results!
    assert l1.rpc.showrunes() == {'runes': [{'rune':
                                             'OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA==',
                                             'unique_id': '0', 'restrictions':
                                             [], 'restrictions_as_english': ''},
                                            {'rune':
                                             'geZmO6U7yqpHn-moaX93FVMVWrDRfSNY4AXx9ypLcqg9MQ==',
                                             'unique_id': '1', 'restrictions':
                                             [], 'restrictions_as_english': ''}]}


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Depends on canned sqlite3 db")
@unittest.skipIf(TEST_NETWORK != 'regtest', 'canned sqlite3 db is regtest')
def test_commando_blacklist_migration(node_factory):
    """Test migration from commando's datastore using db from test_commando_blacklist"""
    l1 = node_factory.get_node(dbfile='commando_blacklist.sqlite3.xz',
                               options={'database-upgrade': True})

    # This happens really early in logs!
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_logs(['Transferring commando blacklist to db: '] * 2)

    # datastore should be empty:
    assert l1.rpc.listdatastore(['commando']) == {'datastore': []}

    # Should match commando results!
    assert l1.rpc.blacklistrune() == {'blacklist': [{'start': 0, 'end': 6},
                                                    {'start': 9, 'end': 9}]}
