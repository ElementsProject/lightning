# This script is used to re-generate all RPC examples for methods listed in doc/schemas/lightning-*.json schema files.
# It uses the pre existing test setup to start nodes, fund channels and execute other RPC calls to generate these examples.
# This test will only run with GENERATE_EXAMPLES=True setup to avoid accidental overwriting of examples with other test executions.
# Set the test TIMEOUT to more than 3 seconds to avoid failures while waiting for the bitcoind response. The `dev-bitcoind-poll` is set to 3 seconds, so a shorter timeout may lead to test failures.
# Note: Different nodes are used to record examples depending upon the availability, quality and volume of the data. For example: Node l1 has been used to listsendpays and l2 for listforwards.

from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from io import BytesIO
from pyln.client import RpcError, Millisatoshi
from pyln.proto.onion import TlvPayload
from utils import only_one, mine_funding_to_announce, sync_blockheight, wait_for, first_scid
import os
import re
import time
import pytest
import unittest
import json
import logging
import ast
import struct
import subprocess

CWD = os.getcwd()
REGENERATING_RPCS = []
ALL_METHOD_NAMES = []
RPCS_STATUS = []
ALL_RPC_EXAMPLES = {}
GENERATE_EXAMPLES = True

FUND_WALLET_AMOUNT_SAT = 200000000
FUND_CHANNEL_AMOUNT_SAT = 10**6
LOG_FILE = 'autogenerate-examples-status.log'

if os.path.exists(LOG_FILE):
    open(LOG_FILE, 'w').close()

logging.basicConfig(level=logging.INFO,
                    format='%(levelname)s - %(message)s',
                    handlers=[
                        # logging.FileHandler(LOG_FILE),
                        logging.StreamHandler()
                    ])

logger = logging.getLogger(__name__)


class TaskFinished(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def update_example(node, method, params, res=None, description=None, execute=True, filename=None):
    """Update examples in JSON files with rpc calls and responses"""
    try:
        def replace_local_paths(data, replacements):
            """Replace local paths in JSON objects"""
            try:
                # For dictionary or list, recursively replace paths
                if isinstance(data, dict):
                    return {k: replace_local_paths(v, replacements) for k, v in data.items()}
                elif isinstance(data, list):
                    return [replace_local_paths(v, replacements) for v in data]
                # Replace when it is string
                elif isinstance(data, str):
                    for old_path, new_path in replacements:
                        data = re.sub(old_path, new_path, data)
                    return data
                # For other data types, return as is
                else:
                    return data
            except Exception as e:
                logger.error(f'Error in replacing local paths: {e}')

        def replace_with_example_values(schema, res, idx):
            """Replace the response values with the 'example_values' from the schema"""
            def update_value(schema, res, idx):
                if isinstance(res, dict):
                    for key, value in res.items():
                        if key in schema.get('properties', {}):
                            prop_schema = schema['properties'][key]
                            if 'example_values' in prop_schema:
                                if prop_schema['example_values'][idx]:
                                    res[key] = prop_schema['example_values'][idx]
                            else:
                                update_value(prop_schema, value, idx)
                elif isinstance(res, list):
                    for index, item in enumerate(res):
                        if 'items' in schema:
                            update_value(schema['items'], item, idx)

            update_value(schema['response'], res, idx)
            return res

        def format_json_with_jq(json_data):
            """Formats the JSON data with jq to avoid check-fmt-schemas errors.
                It is because check-fmt-schemas uses jq to format the JSON data and compare the difference.
                For example, jq will convert 18446744073709551685 to 18446744073709552000 before comparing.
                JQ behaves this way because it uses C doubles to represent numbers, and on pretty much all
                modern systems that's an IEEE 754 double, which can only represent integers without loss
                between -2^53..2^53. 125276004817190914 is about 14 times larger than the largest integer
                that jq can represent losslessly, therefore jq can only approximate it.
                Reference: https://github.com/jqlang/jq/issues/369
            """
            jq_command = 'jq .'
            if not isinstance(json_data, str):
                json_data = json.dumps(json_data)

            # Run the jq command and capture the output
            result = subprocess.run(
                jq_command,
                input=json_data,
                text=True,
                capture_output=True,
                shell=True
            )
            if result.returncode != 0:
                logger.error(f"Error running jq: {result.stderr}")
            return json.loads(result.stdout)

        global CWD, ALL_RPC_EXAMPLES, REGENERATING_RPCS, RPCS_STATUS
        # Usually file name is same as method name, but `sql` is an exception;
        # For sql, the `sql-template` file should be updated with examples then this template with finally generate the sql file with tables
        # See doc/Makefile `doc/schemas/lightning-sql.json` for more details
        file_path = os.path.join(CWD, 'doc', 'schemas', f'lightning-{method}.json') if filename is None else os.path.join(CWD, 'doc', 'schemas', f'lightning-{filename}.json')
        with open(file_path, 'r+', encoding='utf-8') as file:
            schema = json.load(file)
            method_id = len(schema['examples']) + 1 if 'examples' in schema else 1
            req = {
                'id': f'example:{method}#{method_id}',
                'method': method,
                'params': params
            }
            logger.info(f'Method \'{method}\', Params {params}')
            # Execute the RPC call and get the response
            if execute:
                res = node.rpc.call(method, params)
            logger.info(f'{method} response: {res}')
            # Return response without updating the file because user doesn't want to update the example
            # Executing the method and returning the response is useful for further example updates
            if method not in REGENERATING_RPCS:
                return res
            else:
                # Replace local path in the request with default path
                if method == 'plugin' and 'plugin' in req['params']:
                    req['params']['plugin'] = req['params']['plugin'].replace(CWD, '/root/lightning')
                methods_to_replace_path = ['commando', 'listconfigs', 'plugin']
                # Replace local paths in responses to ensure the example's consistency for different users
                if method in methods_to_replace_path:
                    replacements = [
                        (CWD, '/root/lightning'),
                        (r'/tmp/ltests-[^/]+/test_generate_examples_[^/]+/lightning-[^/]+', '/tmp/.lightning')
                    ]
                    res = replace_local_paths(res, replacements)
                # Format the JSON data with jq to avoid check-fmt-schemas errors
                res = format_json_with_jq(res)
                res = replace_with_example_values(schema, res, method_id - 1)
                # Create the example key with description, request & response
                schema.setdefault('examples', []).append({'request': req, 'response': res} if description is None else {'description': description, 'request': req, 'response': res})
                # Update the file with the new example
                file.seek(0)
                json.dump(schema, file, indent=2, ensure_ascii=False)
                file.write('\n')
                file.truncate()
            logger.info(f'Updated {method}#{method_id}')
            for rpc in ALL_RPC_EXAMPLES:
                if rpc['method'] == method:
                    rpc['executed'] += 1
                    if rpc['executed'] == rpc['num_examples']:
                        RPCS_STATUS[REGENERATING_RPCS.index(method)] = True
                    break
            # Exit if listed commands have been executed
            if all(RPCS_STATUS):
                raise TaskFinished('All Done!!!')
            return res
    except FileNotFoundError as fnf_error:
        logger.error(f'File not found error {fnf_error} at: {file_path}')


def setup_test_nodes(node_factory, bitcoind):
    """Sets up six test nodes for various transaction scenarios:
        l1, l2, l3 for transactions and forwards
        l4 for complex transactions (sendpayment, keysend, renepay)
        l5 for keysend with routehints and channel backup & recovery
        l5, l6 for backup and recovery
        l7, l8 for splicing (added later)
        l9, l10 for low level fundchannel examples (added later)
        l11, l12 for low level openchannel examples (added later)
        l13 for recover (added later)
        l1->l2, l2->l3, l3->l4, l2->l5 (unannounced), l9->l10, l11->l12
        l1.info['id']: 0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518
        l2.info['id']: 022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59
        l3.info['id']: 035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d
        l4.info['id']: 0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199
        l5.info['id']: 032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e
        l6.info['id']: 0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b6518
    """
    try:
        global FUND_WALLET_AMOUNT_SAT, FUND_CHANNEL_AMOUNT_SAT
        options = [
            {
                'experimental-dual-fund': None,
                'experimental-offers': None,
                'may_reconnect': True,
                'dev-hsmd-no-preapprove-check': None,
                'allow-deprecated-apis': True,
                'allow_bad_gossip': True,
                'broken_log': '.*',  # plugin-topology: DEPRECATED API USED: *, lightningd-3: had memleak messages, lightningd: MEMLEAK:, lightningd: init_cupdate for unknown scid etc.
                'dev-bitcoind-poll': 3,  # Default 1; increased to avoid rpc failures
            }.copy()
            for i in range(6)
        ]
        l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=options)
        # Upgrade wallet
        # Write the data/p2sh_wallet_hsm_secret to the hsm_path, so node can spend funds at p2sh_wrapped_addr
        p2sh_wrapped_addr = '2N2V4ee2vMkiXe5FSkRqFjQhiS9hKqNytv3'
        update_example(node=l1, method='upgradewallet', params={})
        txid = bitcoind.rpc.sendtoaddress(p2sh_wrapped_addr, 20000000 / 10 ** 8)
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('Owning output .* txid {} CONFIRMED'.format(txid))
        # Doing it with 'reserved ok' should have 1. We use a big feerate so we can get over the RBF hump
        update_example(node=l1, method='upgradewallet', params={'feerate': 'urgent', 'reservedok': True})

        # Fund node wallets for further transactions
        fund_nodes = [l1, l2, l3, l4, l5]
        for node in fund_nodes:
            node.fundwallet(FUND_WALLET_AMOUNT_SAT)
        # Connect nodes and fund channels
        update_example(node=l2, method='getinfo', params={})
        update_example(node=l1, method='connect', params={'id': l2.info['id'], 'host': 'localhost', 'port': l2.daemon.port})
        update_example(node=l2, method='connect', params={'id': l3.info['id'], 'host': 'localhost', 'port': l3.daemon.port})
        l3.rpc.connect(l4.info['id'], 'localhost', l4.port)
        l2.rpc.connect(l5.info['id'], 'localhost', l5.port)
        c12, _ = l1.fundchannel(l2, FUND_CHANNEL_AMOUNT_SAT)
        c23, c23res = l2.fundchannel(l3, FUND_CHANNEL_AMOUNT_SAT)
        c34, _ = l3.fundchannel(l4, FUND_CHANNEL_AMOUNT_SAT)
        c25, _ = l2.fundchannel(l5, announce_channel=False)
        mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])
        l1.wait_channel_active(c12)
        l1.wait_channel_active(c23)
        l1.wait_channel_active(c34)
        # Balance these newly opened channels
        l1.rpc.pay(l2.rpc.invoice('500000sat', 'lbl balance l1 to l2', 'description send some sats l1 to l2')['bolt11'])
        l2.rpc.pay(l3.rpc.invoice('500000sat', 'lbl balance l2 to l3', 'description send some sats l2 to l3')['bolt11'])
        l2.rpc.pay(l5.rpc.invoice('500000sat', 'lbl balance l2 to l5', 'description send some sats l2 to l5')['bolt11'])
        l3.rpc.pay(l4.rpc.invoice('500000sat', 'lbl balance l3 to l4', 'description send some sats l3 to l4')['bolt11'])
        return l1, l2, l3, l4, l5, l6, c12, c23, c25, c34, c23res
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in setting up nodes: {e}')


def generate_transactions_examples(l1, l2, l3, l4, l5, c25, bitcoind):
    """Generate examples for various transactions and forwards"""
    try:
        logger.info('Simple Transactions Start...')
        global FUND_CHANNEL_AMOUNT_SAT
        # Simple Transactions by creating invoices, paying invoices, keysends
        inv_l31 = update_example(node=l3, method='invoice', params={'amount_msat': 10**4, 'label': 'lbl_l31', 'description': 'Invoice description l31'})
        route_l1_l3 = update_example(node=l1, method='getroute', params={'id': l3.info['id'], 'amount_msat': 10**4, 'riskfactor': 1})['route']
        inv_l32 = update_example(node=l3, method='invoice', params={'amount_msat': '50000msat', 'label': 'lbl_l32', 'description': 'l32 description'})
        update_example(node=l2, method='getroute', params={'id': l4.info['id'], 'amount_msat': 500000, 'riskfactor': 10, 'cltv': 9})
        update_example(node=l1, method='sendpay', params={'route': route_l1_l3, 'payment_hash': inv_l31['payment_hash'], 'payment_secret': inv_l31['payment_secret']})
        update_example(node=l1, method='waitsendpay', params={'payment_hash': inv_l31['payment_hash']})
        update_example(node=l1, method='keysend', params={'destination': l3.info['id'], 'amount_msat': 10000})
        update_example(node=l1, method='keysend', params={'destination': l4.info['id'], 'amount_msat': 10000000, 'extratlvs': {'133773310': '68656c6c6f776f726c64', '133773312': '66696c7465726d65'}})
        routehints = [[{
            'scid': only_one([channel for channel in l2.rpc.listpeerchannels()['channels'] if channel['peer_id'] == l3.info['id']])['alias']['remote'],
            'id': l2.info['id'],
            'feebase': '1msat',
            'feeprop': 10,
            'expirydelta': 9,
        }]]
        update_example(node=l1, method='keysend', params={'destination': l3.info['id'], 'amount_msat': 10000, 'routehints': routehints})
        inv_l11 = l1.rpc.invoice('10000msat', 'lbl_l11', 'l11 description')
        inv_l21 = l2.rpc.invoice('any', 'lbl_l21', 'l21 description')
        inv_l22 = l2.rpc.invoice('200000msat', 'lbl_l22', 'l22 description')
        inv_l33 = l3.rpc.invoice('100000msat', 'lbl_l33', 'l33 description')
        inv_l34 = l3.rpc.invoice(4000, 'failed', 'failed description')
        update_example(node=l1, method='pay', params=[inv_l32['bolt11']])
        update_example(node=l2, method='pay', params={'bolt11': inv_l33['bolt11']})

        # Hops, create and send onion for onion routing
        def truncate_encode(i: int):
            """Encode a tu64 (or tu32 etc) value"""
            try:
                ret = struct.pack("!Q", i)
                while ret.startswith(b'\0'):
                    ret = ret[1:]
                return ret
            except Exception as e:
                logger.error(f'Error in encoding: {e}')

        def serialize_payload_tlv(n, blockheight: int = 0):
            """Serialize payload according to BOLT #4: Onion Routing Protocol"""
            try:
                block, tx, out = n['channel'].split('x')
                payload = TlvPayload()
                b = BytesIO()
                b.write(truncate_encode(int(n['amount_msat'])))
                payload.add_field(2, b.getvalue())
                b = BytesIO()
                b.write(truncate_encode(blockheight + n['delay']))
                payload.add_field(4, b.getvalue())
                b = BytesIO()
                b.write(struct.pack("!Q", int(block) << 40 | int(tx) << 16 | int(out)))
                payload.add_field(6, b.getvalue())
                return payload.to_bytes().hex()
            except Exception as e:
                logger.error(f'Error in serializing payload: {e}')

        def serialize_payload_final_tlv(n, payment_secret: str, blockheight: int = 0):
            """Serialize the last payload according to BOLT #4: Onion Routing Protocol"""
            try:
                payload = TlvPayload()
                b = BytesIO()
                b.write(truncate_encode(int(n['amount_msat'])))
                payload.add_field(2, b.getvalue())
                b = BytesIO()
                b.write(truncate_encode(blockheight + n['delay']))
                payload.add_field(4, b.getvalue())
                b = BytesIO()
                b.write(bytes.fromhex(payment_secret))
                b.write(truncate_encode(int(n['amount_msat'])))
                payload.add_field(8, b.getvalue())
                return payload.to_bytes().hex()
            except Exception as e:
                logger.error(f'Error in serializing final payload: {e}')

        blockheight = l1.rpc.getinfo()['blockheight']
        amt = 10**3
        route = l1.rpc.getroute(l4.info['id'], amt, 10)['route']
        inv = l4.rpc.invoice(amt, "lbl l4", "desc l4")
        first_hop = route[0]
        hops = []
        for h, n in zip(route[:-1], route[1:]):
            hops.append({'pubkey': h['id'], 'payload': serialize_payload_tlv(n, blockheight)})
        hops.append({'pubkey': route[-1]['id'], 'payload': serialize_payload_final_tlv(route[-1], inv['payment_secret'], blockheight)})
        onion = update_example(node=l1, method='createonion', params={'hops': hops, 'assocdata': inv['payment_hash']})
        update_example(node=l1, method='createonion', params=[hops, inv['payment_hash'], '41' * 32])
        update_example(node=l1, method='sendonion', params={'onion': onion['onion'], 'first_hop': first_hop, 'payment_hash': inv['payment_hash']})
        l1.rpc.waitsendpay(payment_hash=inv['payment_hash'])

        # Close channels examples
        update_example(node=l2, method='close', params={'id': l3.info['id'], 'unilateraltimeout': 1})
        update_example(node=l3, method='close', params={'id': l4.info['id'], 'destination': l4.rpc.newaddr()['bech32']})
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l1, l2, l3, l4])

        # Channel 2 to 3 is closed, l1->l3 payment will fail where `failed` forward will be saved on l2
        l1.rpc.sendpay(route_l1_l3, inv_l34['payment_hash'], payment_secret=inv_l34['payment_secret'])
        with pytest.raises(RpcError):
            l1.rpc.waitsendpay(inv_l34['payment_hash'])

        # Reopen channels for further examples
        c23, _ = l2.fundchannel(l3, FUND_CHANNEL_AMOUNT_SAT)
        l3.fundchannel(l4, FUND_CHANNEL_AMOUNT_SAT)
        mine_funding_to_announce(bitcoind, [l3, l4])
        l2.wait_channel_active(c23)
        update_example(node=l2, method='setchannel', params={'id': c23, 'ignorefeelimits': True})
        update_example(node=l2, method='setchannel', params={'id': c25, 'feebase': 4000, 'feeppm': 300, 'enforcedelay': 0})

        # Some more invoices for signing and preapproving
        inv_l12 = l1.rpc.invoice(1000, 'label inv_l12', 'description inv_l12')['bolt11']
        inv_l24 = l2.rpc.invoice(123000, 'label inv_l24', 'description inv_l24', 3600)['bolt11']
        inv_l25 = l2.rpc.invoice(124000, 'label inv_l25', 'description inv_l25', 3600)['bolt11']
        inv_l26 = l2.rpc.invoice(125000, 'label inv_l26', 'description inv_l26', 3600)['bolt11']
        update_example(node=l2, method='signinvoice', params={'invstring': inv_l12})
        update_example(node=l3, method='signinvoice', params=[inv_l26])
        update_example(node=l1, method='preapprovekeysend', params={'destination': l2.info['id'], 'payment_hash': '00' * 32, 'amount_msat': 1000})
        update_example(node=l5, method='preapprovekeysend', params=[l5.info['id'], '01' * 32, 2000])
        update_example(node=l1, method='preapproveinvoice', params={'bolt11': inv_l24})
        update_example(node=l1, method='preapproveinvoice', params=[inv_l25])
        inv_req = update_example(node=l2, method='invoicerequest', params={'amount': 1000000, 'description': 'Simple test'})
        update_example(node=l1, method='sendinvoice', params={'invreq': inv_req['bolt12'], 'label': 'test sendinvoice'})
        inv_l13 = l1.rpc.invoice(amount_msat=100000, label='lbl_l13', description='l13 description', preimage='01' * 32)
        update_example(node=l2, method='createinvoice', params={'invstring': inv_l13['bolt11'], 'label': 'lbl_l13', 'preimage': '01' * 32})
        logger.info('Simple Transactions Done!')
        return inv_l11, inv_l21, inv_l22, inv_l31, inv_l32, inv_l34
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating transactions examples: {e}')


def generate_runes_examples(l1, l2, l3):
    """Covers all runes related examples"""
    try:
        logger.info('Runes Start...')
        # Runes
        trimmed_id = l1.info['id'][:20]
        rune_l21 = update_example(node=l2, method='createrune', params={}, description=['This creates a fresh rune which can do anything:'])
        rune_l22 = update_example(node=l2, method='createrune', params={'rune': rune_l21['rune'], 'restrictions': 'readonly'},
                                  description=['We can add restrictions to that rune, like so:',
                                               '',
                                               'The `readonly` restriction is a short-cut for two restrictions:',
                                               '',
                                               '1: `[\'method^list\', \'method^get\', \'method=summary\']`: You may call list, get or summary.',
                                               '',
                                               '2: `[\'method/listdatastore\']`: But not listdatastore: that contains sensitive stuff!'
                                               ])
        update_example(node=l2, method='createrune', params={'rune': rune_l21['rune'], 'restrictions': [['method^list', 'method^get', 'method=summary'], ['method/listdatastore']]}, description=['We can do the same manually (readonly), like so:'])
        rune_l23 = update_example(node=l2, method='createrune', params={'restrictions': [[f'id^{trimmed_id}'], ['method=listpeers']]}, description=[f'This will allow the rune to be used for id starting with {trimmed_id}, and for the method listpeers:'])
        rune_l24 = update_example(node=l2, method='createrune', params={'restrictions': [['method=pay'], ['pnameamountmsat<10000']]}, description=['This will allow the rune to be used for the method pay, and for the parameter amount\\_msat to be less than 10000:'])
        update_example(node=l2, method='createrune', params={'restrictions': [[f'id={l1.info["id"]}'], ['method=listpeers'], ['pnum=1'], [f'pnameid={l1.info["id"]}', f'parr0={l1.info["id"]}']]}, description=["Let's create a rune which lets a specific peer run listpeers on themselves:"])
        rune_l25 = update_example(node=l2, method='createrune', params={'restrictions': [[f'id={l1.info["id"]}'], ['method=listpeers'], ['pnum=1'], [f'pnameid^{trimmed_id}', f'parr0^{trimmed_id}']]}, description=["This allows `listpeers` with 1 argument (`pnum=1`), which is either by name (`pnameid`), or position (`parr0`). We could shorten this in several ways: either allowing only positional or named parameters, or by testing the start of the parameters only. Here's an example which only checks the first 10 bytes of the `listpeers` parameter:"])
        update_example(node=l2, method='createrune', params=[rune_l25['rune'], [['time<"$(($(date +%s) + 24*60*60))"', 'rate=2']]], description=["Before we give this to our peer, let's add two more restrictions: that it only be usable for 24 hours from now (`time<`), and that it can only be used twice a minute (`rate=2`). `date +%s` can give us the current time in seconds:"])
        update_example(node=l2, method='commando-listrunes', params={'rune': rune_l23['rune']})
        update_example(node=l2, method='commando-listrunes', params={})
        update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l22['rune'], 'method': 'getinfo', 'params': {}})
        update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l23['rune'], 'method': 'listpeers', 'params': [l3.info['id']]})
        inv_l23 = l2.rpc.invoice('any', 'lbl_l23', 'l23 description')
        update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l24['rune'], 'method': 'pay', 'params': {'bolt11': inv_l23['bolt11'], 'amount_msat': 9900}})
        update_example(node=l2, method='checkrune', params={'nodeid': l2.info['id'], 'rune': rune_l22['rune'], 'method': 'listpeers', 'params': {}})
        update_example(node=l2, method='checkrune', params={'nodeid': l2.info['id'], 'rune': rune_l24['rune'], 'method': 'pay', 'params': {'amount_msat': 9999}})
        update_example(node=l2, method='showrunes', params={'rune': rune_l21['rune']})
        update_example(node=l2, method='showrunes', params={})
        update_example(node=l2, method='commando-blacklist', params={'start': 1})
        update_example(node=l2, method='commando-blacklist', params={'start': 2, 'end': 3})
        update_example(node=l2, method='blacklistrune', params={'start': 1})
        update_example(node=l2, method='blacklistrune', params={'start': 0, 'end': 2})
        update_example(node=l2, method='blacklistrune', params={'start': 3, 'end': 4})

        # Commando runes
        rune_l11 = update_example(node=l1, method='commando-rune', params={}, description=['This creates a fresh rune which can do anything:'])
        update_example(node=l1, method='commando-rune', params={'rune': rune_l11['rune'], 'restrictions': 'readonly'},
                       description=['We can add restrictions to that rune, like so:',
                                    '',
                                    'The `readonly` restriction is a short-cut for two restrictions:',
                                    '',
                                    '1: `[\'method^list\', \'method^get\', \'method=summary\']`: You may call list, get or summary.',
                                    '',
                                    '2: `[\'method/listdatastore\']`: But not listdatastore: that contains sensitive stuff!'
                                    ])
        update_example(node=l1, method='commando-rune', params={'rune': rune_l11['rune'], 'restrictions': [['method^list', 'method^get', 'method=summary'], ['method/listdatastore']]}, description=['We can do the same manually (readonly), like so:'])
        update_example(node=l1, method='commando-rune', params={'restrictions': [[f'id^{trimmed_id}'], ['method=listpeers']]}, description=[f'This will allow the rune to be used for id starting with {trimmed_id}, and for the method listpeers:'])
        update_example(node=l1, method='commando-rune', params={'restrictions': [['method=pay'], ['pnameamountmsat<10000']]}, description=['This will allow the rune to be used for the method pay, and for the parameter amount\\_msat to be less than 10000:'])
        update_example(node=l1, method='commando-rune', params={'restrictions': [[f'id={l1.info["id"]}'], ['method=listpeers'], ['pnum=1'], [f'pnameid={l1.info["id"]}', f'parr0={l1.info["id"]}']]}, description=["Let's create a rune which lets a specific peer run listpeers on themselves:"])
        rune_l15 = update_example(node=l1, method='commando-rune', params={'restrictions': [[f'id={l1.info["id"]}'], ['method=listpeers'], ['pnum=1'], [f'pnameid^{trimmed_id}', f'parr0^{trimmed_id}']]}, description=["This allows `listpeers` with 1 argument (`pnum=1`), which is either by name (`pnameid`), or position (`parr0`). We could shorten this in several ways: either allowing only positional or named parameters, or by testing the start of the parameters only. Here's an example which only checks the first 10 bytes of the `listpeers` parameter:"])
        update_example(node=l1, method='commando-rune', params=[rune_l15['rune'], [['time<"$(($(date +%s) + 24*60*60))"', 'rate=2']]], description=["Before we give this to our peer, let's add two more restrictions: that it only be usable for 24 hours from now (`time<`), and that it can only be used twice a minute (`rate=2`). `date +%s` can give us the current time in seconds:"])
        logger.info('Runes Done!')
        return rune_l21
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating runes examples: {e}')


def generate_datastore_examples(l2):
    """Covers all datastore related examples"""
    try:
        logger.info('Datastore Start...')
        update_example(node=l2, method='datastore', params={'key': 'somekey', 'hex': '61', 'mode': 'create-or-append'})
        update_example(node=l2, method='datastore', params={'key': ['test', 'name'], 'string': 'saving data to the store', 'mode': 'must-create'})
        update_example(node=l2, method='datastore', params={'key': 'otherkey', 'string': 'foo', 'mode': 'must-create'})
        update_example(node=l2, method='datastore', params={'key': 'otherkey', 'string': 'bar', 'mode': 'must-append', 'generation': 0})
        update_example(node=l2, method='datastoreusage', params={})
        update_example(node=l2, method='datastoreusage', params={'key': ['test', 'name']})
        update_example(node=l2, method='datastoreusage', params={'key': 'otherkey'})
        update_example(node=l2, method='listdatastore', params={'key': ['test']})
        update_example(node=l2, method='listdatastore', params={'key': 'otherkey'})
        update_example(node=l2, method='deldatastore', params={'key': ['test', 'name']})
        update_example(node=l2, method='deldatastore', params={'key': 'otherkey', 'generation': 1})
        logger.info('Datastore Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating datastore examples: {e}')


def generate_bookkeeper_examples(l2, l3, c23_chan_id):
    """Generates all bookkeeper rpc examples"""
    try:
        logger.info('Bookkeeper Start...')
        update_example(node=l2, method='funderupdate', params={})
        update_example(node=l2, method='funderupdate', params={'policy': 'fixed', 'policy_mod': '50000sat', 'min_their_funding_msat': 1000, 'per_channel_min_msat': '1000sat', 'per_channel_max_msat': '500000sat', 'fund_probability': 100, 'fuzz_percent': 0, 'leases_only': False})
        update_example(node=l2, method='bkpr-inspect', params={'account': c23_chan_id})
        update_example(node=l2, method='bkpr-dumpincomecsv', params=['koinly', 'koinly.csv'])
        update_example(node=l2, method='bkpr-channelsapy', params={})
        update_example(node=l3, method='bkpr-listbalances', params={})
        update_example(node=l3, method='bkpr-listaccountevents', params={})
        update_example(node=l3, method='bkpr-listaccountevents', params=[c23_chan_id])
        update_example(node=l3, method='bkpr-listincome', params={})

        # listincome and editing descriptions
        listincome_result = update_example(node=l3, method='bkpr-listincome', params={'consolidate_fees': False})
        invoice = next((event for event in listincome_result['income_events'] if 'payment_id' in event), None)
        utxo_event = next((event for event in listincome_result['income_events'] if 'outpoint' in event), None)
        update_example(node=l3, method='bkpr-editdescriptionbypaymentid', params={'payment_id': invoice['payment_id'], 'description': 'edited invoice description'})
        # Try to edit a payment_id that does not exist
        update_example(node=l3, method='bkpr-editdescriptionbypaymentid', params={'payment_id': 'c97b61113636256111835c0204d70111c42f19069cefdc659849a6afc6b595a4', 'description': 'edited invoice description'})
        update_example(node=l3, method='bkpr-editdescriptionbyoutpoint', params={'outpoint': utxo_event['outpoint'], 'description': 'edited utxo description'})
        # Try to edit an outpoint that does not exist
        update_example(node=l3, method='bkpr-editdescriptionbyoutpoint', params={'outpoint': '6472b4c9d39d8478ed9c848df7a62a512d953a4b2e6e7b09902d76a7bbb761ca:1', 'description': 'edited utxo description'})

        logger.info('Bookkeeper Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating bookkeeper examples: {e}')


def generate_offers_renepay_examples(l1, l2, inv_l21, inv_l34):
    """Covers all offers and renepay related examples"""
    try:
        logger.info('Offers and Renepay Start...')

        # Offers & Offers Lists
        offer_l21 = update_example(node=l2, method='offer', params={'amount': '10000msat', 'description': 'Fish sale!'})
        offer_l22 = update_example(node=l2, method='offer', params={'amount': '1000sat', 'description': 'Coffee', 'quantity_max': 10})
        offer_l23 = l2.rpc.offer('2000sat', 'Offer to Disable')
        update_example(node=l1, method='fetchinvoice', params={'offer': offer_l21['bolt12'], 'payer_note': 'Thanks for the fish!'})
        update_example(node=l1, method='fetchinvoice', params={'offer': offer_l22['bolt12'], 'amount_msat': 2000000, 'quantity': 2})
        update_example(node=l2, method='disableoffer', params={'offer_id': offer_l23['offer_id']})
        update_example(node=l2, method='listoffers', params={'active_only': True})
        update_example(node=l2, method='listoffers', params=[offer_l23['offer_id']])

        # Invoice Requests
        inv_req_l1_l22 = update_example(node=l2, method='invoicerequest', params={'amount': '10000sat', 'description': 'Requesting for invoice', 'issuer': 'clightning store'})
        update_example(node=l2, method='disableinvoicerequest', params={'invreq_id': inv_req_l1_l22['invreq_id']})
        update_example(node=l2, method='listinvoicerequests', params=[inv_req_l1_l22['invreq_id']])
        update_example(node=l2, method='listinvoicerequests', params={})

        # Renepay
        update_example(node=l1, method='renepay', params={'invstring': inv_l21['bolt11'], 'amount_msat': 400000})
        update_example(node=l2, method='renepay', params={'invstring': inv_l34['bolt11']})
        update_example(node=l1, method='renepaystatus', params={'invstring': inv_l21['bolt11']})
        logger.info('Offers and Renepay Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating offers or renepay examples: {e}')


def generate_list_examples(l1, l2, l3, c12, c23, inv_l31, inv_l32):
    """Generates lists rpc examples"""
    try:
        logger.info('Lists Start...')

        # Transactions Lists
        update_example(node=l1, method='listfunds', params={})
        update_example(node=l2, method='listforwards', params={'in_channel': c12, 'out_channel': c23, 'status': 'settled'})
        update_example(node=l2, method='listforwards', params={})
        update_example(node=l2, method='listinvoices', params={'label': 'lbl_l21'})
        update_example(node=l2, method='listinvoices', params={})
        update_example(node=l1, method='listhtlcs', params=[c12])
        update_example(node=l1, method='listhtlcs', params={})
        update_example(node=l1, method='listsendpays', params={'bolt11': inv_l31['bolt11']})
        update_example(node=l1, method='listsendpays', params={})
        update_example(node=l1, method='listtransactions', params={})
        update_example(node=l2, method='listpays', params={'bolt11': inv_l32['bolt11']})
        update_example(node=l2, method='listpays', params={})
        update_example(node=l3, method='listclosedchannels', params={})

        # Network & Nodes Lists
        update_example(node=l2, method='listconfigs', params={'config': 'network'})
        update_example(node=l2, method='listconfigs', params={'config': 'experimental-dual-fund'})
        # Schema checker error: listconfigs.json: Additional properties are not allowed ('plugin' was unexpected)
        l2.rpc.jsonschemas = {}
        update_example(node=l2, method='listconfigs', params={})
        update_example(node=l2, method='listsqlschemas', params={'table': 'offers'})
        update_example(node=l2, method='listsqlschemas', params=['closedchannels'])
        update_example(node=l1, method='listpeerchannels', params={'id': l2.info['id']})
        update_example(node=l1, method='listpeerchannels', params={})
        update_example(node=l1, method='listchannels', params={'short_channel_id': c12})
        update_example(node=l1, method='listchannels', params={})
        update_example(node=l2, method='listnodes', params={'id': l3.info['id']})
        update_example(node=l2, method='listnodes', params={})
        update_example(node=l2, method='listpeers', params={'id': l3.info['id']})
        update_example(node=l2, method='listpeers', params={})
        logger.info('Lists Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating lists examples: {e}')


def generate_wait_examples(l1, l2, bitcoind, executor):
    """Generates wait examples"""
    try:
        logger.info('Wait Start...')
        inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')
        inv2 = l2.rpc.invoice(2000, 'inv2', 'inv2')
        inv3 = l2.rpc.invoice(3000, 'inv3', 'inv3')
        inv4 = l2.rpc.invoice(4000, 'inv4', 'inv4')
        inv5 = l2.rpc.invoice(5000, 'inv5', 'inv5')

        # Wait invoice
        wi3 = executor.submit(l2.rpc.waitinvoice, 'inv3')
        time.sleep(1)
        l1.rpc.pay(inv2['bolt11'])
        time.sleep(1)
        wi2res = executor.submit(l2.rpc.waitinvoice, 'inv2').result(timeout=5)
        update_example(node=l2, method='waitinvoice', params={'label': 'inv2'}, res=wi2res, execute=False)

        l1.rpc.pay(inv3['bolt11'])
        wi3res = wi3.result(timeout=5)
        update_example(node=l2, method='waitinvoice', params=['inv3'], res=wi3res, execute=False)

        # Wait any invoice
        wai = executor.submit(l2.rpc.waitanyinvoice)
        time.sleep(1)
        l1.rpc.pay(inv5['bolt11'])
        l1.rpc.pay(inv4['bolt11'])
        waires = wai.result(timeout=5)
        update_example(node=l2, method='waitanyinvoice', params={}, res=waires, execute=False)
        pay_index = waires['pay_index']
        wai_pay_index_res = executor.submit(l2.rpc.waitanyinvoice, pay_index, 0).result(timeout=5)
        update_example(node=l2, method='waitanyinvoice', params={'lastpay_index': pay_index, 'timeout': 0}, res=wai_pay_index_res, execute=False)

        # Wait with subsystem examples
        update_example(node=l2, method='wait', params={'subsystem': 'invoices', 'indexname': 'created', 'nextvalue': 0})

        wspres_l1 = l1.rpc.wait(subsystem='sendpays', indexname='created', nextvalue=0)
        nextvalue = int(wspres_l1['created']) + 1
        wsp_created_l1 = executor.submit(l1.rpc.call, 'wait', {'subsystem': 'sendpays', 'indexname': 'created', 'nextvalue': nextvalue})
        wsp_updated_l1 = executor.submit(l1.rpc.call, 'wait', {'subsystem': 'sendpays', 'indexname': 'updated', 'nextvalue': nextvalue})
        time.sleep(1)
        routestep = {
            'amount_msat': 1000,
            'id': l2.info['id'],
            'delay': 5,
            'channel': first_scid(l1, l2)
        }
        l1.rpc.sendpay([routestep], inv1['payment_hash'], payment_secret=inv1['payment_secret'])
        wspc_res = wsp_created_l1.result(5)
        wspu_res = wsp_updated_l1.result(5)
        update_example(node=l1, method='wait', params={'subsystem': 'sendpays', 'indexname': 'created', 'nextvalue': nextvalue}, res=wspc_res, execute=False)
        update_example(node=l1, method='wait', params=['sendpays', 'updated', nextvalue], res=wspu_res, execute=False)

        # Wait blockheight
        curr_blockheight = l2.rpc.getinfo()['blockheight']
        update_example(node=l2, method='waitblockheight', params={'blockheight': curr_blockheight - 1, 'timeout': 600})
        wait_time = 60
        wbh = executor.submit(l2.rpc.waitblockheight, curr_blockheight + 1, wait_time)
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l2])
        wbhres = wbh.result(5)
        update_example(node=l2, method='waitblockheight', params={'blockheight': curr_blockheight + 1}, res=wbhres, execute=False)
        logger.info('Wait Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating wait examples: {e}')


def generate_utils_examples(l1, l2, l3, l4, l5, l6, c23, c34, inv_l11, inv_l22, rune_l21, bitcoind):
    """Generates other utilities examples"""
    try:
        logger.info('General Utils Start...')
        global CWD, FUND_CHANNEL_AMOUNT_SAT
        update_example(node=l2, method='batching', params={'enable': True})
        update_example(node=l2, method='ping', params={'id': l1.info['id'], 'len': 128, 'pongbytes': 128})
        update_example(node=l2, method='ping', params={'id': l3.info['id'], 'len': 1000, 'pongbytes': 65535})
        update_example(node=l2, method='help', params={'command': 'pay'})
        update_example(node=l2, method='help', params={'command': 'dev'})
        update_example(node=l2, method='setconfig', params=['autoclean-expiredinvoices-age', 300])
        update_example(node=l2, method='setconfig', params={'config': 'min-capacity-sat', 'val': 500000})
        update_example(node=l2, method='addgossip', params={'message': '010078c3314666731e339c0b8434f7824797a084ed7ca3655991a672da068e2c44cb53b57b53a296c133bc879109a8931dc31e6913a4bda3d58559b99b95663e6d52775579447ef5526300e1bb89bc6af8557aa1c3810a91814eafad6d103f43182e17b16644cb38c1d58a8edd094303959a9f1f9d42ff6c32a21f9c118531f512c8679cabaccc6e39dbd95a4dac90e75a258893c3aa3f733d1b8890174d5ddea8003cadffe557773c54d2c07ca1d535c4bf85885f879ae466c16a516e8ffcfec1740e3f5c98ca9ce13f452e867befef5517f306ed6aa5119b79059bcc6f68f329986b665d16de7bc7df64e3537504c91eeabe0e59d3a2b68e4216ead2b0f6e3ef7c000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000670000010000022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d590266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351802e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5702324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b'})
        update_example(node=l2, method='addgossip', params={'message': '0102420526c8eb62ec6999bbee5f1de4841cab734374ec642b7deeb0259e76220bf82e97a241c907d5ff52019655f7f9a614c285bb35690f3a1a2b928d7b2349a79e06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f000067000001000065b32a0e010100060000000000000000000000010000000a000000003b023380'})
        update_example(node=l2, method='deprecations', params={'enable': True})
        update_example(node=l2, method='deprecations', params={'enable': False})
        update_example(node=l2, method='getlog', params={'level': 'unusual'})
        update_example(node=l2, method='notifications', params={'enable': True})
        update_example(node=l2, method='notifications', params={'enable': False})
        update_example(node=l2, method='check', params={'command_to_check': 'sendpay', 'route': [{'amount_msat': 1011, 'id': l3.info['id'], 'delay': 20, 'channel': c23}, {'amount_msat': 1000, 'id': l4.info['id'], 'delay': 10, 'channel': c34}], 'payment_hash': '0000000000000000000000000000000000000000000000000000000000000000'})
        update_example(node=l2, method='check', params={'command_to_check': 'dev', 'subcommand': 'slowcmd', 'msec': 1000})
        update_example(node=l6, method='check', params={'command_to_check': 'recover', 'hsmsecret': '6c696768746e696e672d31000000000000000000000000000000000000000000'})
        update_example(node=l2, method='plugin', params={'subcommand': 'start', 'plugin': os.path.join(CWD, 'tests/plugins/allow_even_msgs.py')})
        update_example(node=l2, method='plugin', params={'subcommand': 'stop', 'plugin': os.path.join(CWD, 'tests/plugins/allow_even_msgs.py')})
        update_example(node=l2, method='plugin', params=['list'])
        update_example(node=l2, method='sendcustommsg', params={'node_id': l3.info['id'], 'msg': '77770012'})

        # Wallet Utils
        address_l21 = update_example(node=l2, method='newaddr', params={})
        address_l22 = update_example(node=l2, method='newaddr', params={'addresstype': 'p2tr'})
        withdraw_l21 = update_example(node=l2, method='withdraw', params={'destination': address_l21['bech32'], 'satoshi': 555555})

        bitcoind.generate_block(4, wait_for_mempool=[withdraw_l21['txid']])
        sync_blockheight(bitcoind, [l2])

        funds_l2 = l2.rpc.listfunds()
        withdraw_l22 = update_example(node=l2, method='withdraw', params={'destination': address_l22['p2tr'], 'satoshi': 'all', 'feerate': '20000perkb', 'minconf': 0, 'utxos': [f"{funds_l2['outputs'][2]['txid']}:{funds_l2['outputs'][2]['output']}"]})
        bitcoind.generate_block(4, wait_for_mempool=[withdraw_l22['txid']])
        update_example(node=l2, method='multiwithdraw', params={'outputs': [{l1.rpc.newaddr()['bech32']: '2222000msat'}, {l1.rpc.newaddr()['bech32']: '3333000msat'}]})
        update_example(node=l2, method='multiwithdraw', params={'outputs': [{l1.rpc.newaddr('p2tr')['p2tr']: 1000}, {l1.rpc.newaddr()['bech32']: 1000}, {l2.rpc.newaddr()['bech32']: 1000}, {l3.rpc.newaddr()['bech32']: 1000}, {l3.rpc.newaddr()['bech32']: 1000}, {l4.rpc.newaddr('p2tr')['p2tr']: 1000}, {l1.rpc.newaddr()['bech32']: 1000}]})
        l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
        l2.rpc.connect(l5.info['id'], 'localhost', l5.port)
        update_example(node=l2, method='disconnect', params={'id': l4.info['id'], 'force': False})
        update_example(node=l2, method='disconnect', params={'id': l5.info['id'], 'force': True})
        update_example(node=l2, method='parsefeerate', params=['unilateral_close'])
        update_example(node=l2, method='parsefeerate', params=['9999perkw'])
        update_example(node=l2, method='parsefeerate', params=[10000])
        update_example(node=l2, method='parsefeerate', params=['urgent'])
        update_example(node=l2, method='feerates', params={'style': 'perkw'})
        update_example(node=l2, method='feerates', params={'style': 'perkb'})
        update_example(node=l2, method='signmessage', params={'message': 'this is a test!'})
        update_example(node=l2, method='signmessage', params={'message': 'message for you'})
        update_example(node=l2, method='checkmessage', params={'message': 'testcase to check new rpc error', 'zbase': 'd66bqz3qsku5fxtqsi37j11pci47ydxa95iusphutggz9ezaxt56neh77kxe5hyr41kwgkncgiu94p9ecxiexgpgsz8daoq4tw8kj8yx', 'pubkey': '03be3b0e9992153b1d5a6e1623670b6c3663f72ce6cf2e0dd39c0a373a7de5a3b7'})
        update_example(node=l2, method='checkmessage', params={'message': 'this is a test!', 'zbase': 'd6tqaeuonjhi98mmont9m4wag7gg4krg1f4txonug3h31e9h6p6k6nbwjondnj46dkyausobstnk7fhyy998bhgc1yr98dfmhb4k54d7'})
        update_example(node=l2, method='decode', params=[rune_l21['rune']])
        update_example(node=l2, method='decode', params=[inv_l22['bolt11']])

        # PSBT
        amount1 = 1000000
        amount2 = 3333333
        result = update_example(node=l1, method='addpsbtoutput', params={'satoshi': amount1, 'locktime': 111}, description=[f'Here is a command to make a PSBT with a {amount1:,} sat output that leads to the on-chain wallet:'])
        update_example(node=l1, method='setpsbtversion', params={'psbt': result['psbt'], 'version': 0})
        result = l1.rpc.addpsbtoutput(amount2, result['psbt'])
        update_example(node=l1, method='addpsbtoutput', params=[amount2, result['psbt']], res=result, execute=False)
        dest = l1.rpc.newaddr('p2tr')['p2tr']
        result = update_example(node=l1, method='addpsbtoutput', params={'satoshi': amount2, 'initialpsbt': result['psbt'], 'destination': dest})
        l1.rpc.addpsbtoutput(amount2, result['psbt'], None, dest)
        update_example(node=l1, method='setpsbtversion', params=[result['psbt'], 2])

        out_total = Millisatoshi(3000000 * 1000)
        funding = l1.rpc.fundpsbt(satoshi=out_total, feerate=7500, startweight=42)
        psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
        saved_input = psbt['tx']['vin'][0]
        l1.rpc.unreserveinputs(funding['psbt'])
        psbt = bitcoind.rpc.createpsbt([{'txid': saved_input['txid'],
                                        'vout': saved_input['vout']}], [])
        out_1_ms = Millisatoshi(funding['excess_msat'])
        output_psbt = bitcoind.rpc.createpsbt([], [{'bcrt1qeyyk6sl5pr49ycpqyckvmttus5ttj25pd0zpvg': float((out_total + out_1_ms).to_btc())}])
        fullpsbt = bitcoind.rpc.joinpsbts([funding['psbt'], output_psbt])
        l1.rpc.reserveinputs(fullpsbt)
        signed_psbt = l1.rpc.signpsbt(fullpsbt)['signed_psbt']
        update_example(node=l1, method='sendpsbt', params={'psbt': signed_psbt})

        # SQL
        update_example(node=l1, filename='sql-template', method='sql', params={'query': 'SELECT id FROM peers'}, description=['A simple peers selection query:'])
        update_example(node=l1, filename='sql-template', method='sql', params=[f'SELECT nodeid,last_timestamp FROM nodes WHERE last_timestamp>=1669578892'], description=["A statement containing `=` needs `-o` in shell:"])
        update_example(node=l1, filename='sql-template', method='sql', params=[f"SELECT nodeid FROM nodes WHERE nodeid != x'{l3.info['id']}'"], description=['If you want to get specific nodeid values from the nodes table:'])
        update_example(node=l1, filename='sql-template', method='sql', params=[f"SELECT nodeid FROM nodes WHERE nodeid IN (x'{l1.info['id']}', x'{l3.info['id']}')"], description=["If you want to compare a BLOB column, `x'hex'` or `X'hex'` are needed:"])
        update_example(node=l1, filename='sql-template', method='sql', params=['SELECT peer_id, short_channel_id, to_us_msat, total_msat, peerchannels_status.status FROM peerchannels INNER JOIN peerchannels_status ON peerchannels_status.row = peerchannels.rowid'], description=['Related tables are usually referenced by JOIN:'])
        update_example(node=l2, filename='sql-template', method='sql', params=['SELECT COUNT(*) FROM forwards'], description=["Simple function usage, in this case COUNT. Strings inside arrays need \", and ' to protect them from the shell:"])
        update_example(node=l1, filename='sql-template', method='sql', params=['SELECT * from peerchannels_features'])
        logger.info('General Utils Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating utils examples: {e}')


def generate_splice_examples(node_factory, bitcoind):
    """Generates splice related examples"""
    try:
        logger.info('Splice Start...')
        global FUND_WALLET_AMOUNT_SAT, FUND_CHANNEL_AMOUNT_SAT
        # Basic setup for l7->l8
        options = [
            {
                'experimental-splicing': None,
                'allow-deprecated-apis': True,
                'allow_bad_gossip': True,
                'broken_log': '.*',
                'dev-bitcoind-poll': 3,
            }.copy()
            for i in range(2)
        ]
        l7, l8 = node_factory.get_nodes(2, opts=options)
        l7.fundwallet(FUND_WALLET_AMOUNT_SAT)
        l7.rpc.connect(l8.info['id'], 'localhost', l8.port)
        c1112, _ = l7.fundchannel(l8, FUND_CHANNEL_AMOUNT_SAT)
        mine_funding_to_announce(bitcoind, [l7, l8])
        l7.wait_channel_active(c1112)
        chan_id = l7.get_channel_id(l8)

        # Splice
        funds_result = l7.rpc.fundpsbt('109000sat', 'slow', 166, excess_as_change=True)
        result = update_example(node=l7, method='splice_init', params={'channel_id': chan_id, 'relative_amount': 100000, 'initialpsbt': funds_result['psbt']})
        result = update_example(node=l7, method='splice_update', params={'channel_id': chan_id, 'psbt': result['psbt']})
        result = l7.rpc.signpsbt(result['psbt'])
        result = update_example(node=l7, method='splice_signed', params={'channel_id': chan_id, 'psbt': result['signed_psbt']})

        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l7])
        l7.daemon.wait_for_log(' to CHANNELD_NORMAL')
        time.sleep(1)

        # Splice out
        funds_result = l7.rpc.addpsbtoutput(100000)

        # Pay with fee by subtracting 5000 from channel balance
        result = update_example(node=l7, method='splice_init', params=[chan_id, -105000, funds_result['psbt']])
        result = update_example(node=l7, method='splice_update', params=[chan_id, result['psbt']])
        result = update_example(node=l7, method='splice_signed', params=[chan_id, result['psbt']])
        update_example(node=l7, method='stop', params={})
        logger.info('Splice Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating splicing examples: {e}')


def generate_channels_examples(node_factory, bitcoind, l1, l3, l4, l5):
    """Generates fundchannel and openchannel related examples"""
    try:
        logger.info('Channels Start...')
        global FUND_WALLET_AMOUNT_SAT, FUND_CHANNEL_AMOUNT_SAT
        # Basic setup for l9->l10 for fundchannel examples
        options = [
            {
                'may_reconnect': True,
                'dev-no-reconnect': None,
                'allow-deprecated-apis': True,
                'allow_bad_gossip': True,
                'broken_log': '.*',
                'dev-bitcoind-poll': 3,
            }.copy()
            for i in range(2)
        ]
        l9, l10 = node_factory.get_nodes(2, opts=options)
        amount = 2 ** 24
        l9.fundwallet(amount + 10000000)
        bitcoind.generate_block(1)
        wait_for(lambda: len(l9.rpc.listfunds()["outputs"]) != 0)
        l9.rpc.connect(l10.info['id'], 'localhost', l10.port)

        fund_start = update_example(node=l9, method='fundchannel_start', params=[l10.info['id'], amount])
        tx_prep = update_example(node=l9, method='txprepare', params=[[{fund_start['funding_address']: amount}]])
        update_example(node=l9, method='fundchannel_cancel', params=[l10.info['id']])
        update_example(node=l9, method='txdiscard', params=[tx_prep['txid']])
        fund_start = update_example(node=l9, method='fundchannel_start', params={'id': l10.info['id'], 'amount': amount})
        tx_prep = update_example(node=l9, method='txprepare', params={'outputs': [{fund_start['funding_address']: amount}]})
        update_example(node=l9, method='fundchannel_complete', params=[l10.info['id'], tx_prep['psbt']])
        update_example(node=l9, method='txsend', params=[tx_prep['txid']])
        l9.rpc.close(l10.info['id'])

        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l9])

        amount = 1000000
        fund_start = l9.rpc.fundchannel_start(l10.info['id'], amount)
        tx_prep = l9.rpc.txprepare([{fund_start['funding_address']: amount}])
        update_example(node=l9, method='fundchannel_cancel', params={'id': l10.info['id']})
        update_example(node=l9, method='txdiscard', params={'txid': tx_prep['txid']})
        funding_addr = l9.rpc.fundchannel_start(l10.info['id'], amount)['funding_address']
        tx_prep = l9.rpc.txprepare([{funding_addr: amount}])
        update_example(node=l9, method='fundchannel_complete', params={'id': l10.info['id'], 'psbt': tx_prep['psbt']})
        update_example(node=l9, method='txsend', params={'txid': tx_prep['txid']})
        l9.rpc.close(l10.info['id'])

        # Basic setup for l11->l12 for openchannel examples
        options = [
            {
                'experimental-dual-fund': None,
                'may_reconnect': True,
                'dev-no-reconnect': None,
                'allow_warning': True,
                'allow-deprecated-apis': True,
                'allow_bad_gossip': True,
                'broken_log': '.*',
                'dev-bitcoind-poll': 3,
            }.copy()
            for i in range(2)
        ]
        l11, l12 = node_factory.get_nodes(2, opts=options)
        l11.fundwallet(FUND_WALLET_AMOUNT_SAT)
        l11.rpc.connect(l12.info['id'], 'localhost', l12.port)
        c78res = l11.rpc.fundchannel(l12.info['id'], FUND_CHANNEL_AMOUNT_SAT)
        chan_id = c78res['channel_id']
        vins = bitcoind.rpc.decoderawtransaction(c78res['tx'])['vin']
        assert(only_one(vins))
        prev_utxos = ["{}:{}".format(vins[0]['txid'], vins[0]['vout'])]

        l11.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')
        chan = only_one(l11.rpc.listpeerchannels(l12.info['id'])['channels'])
        rate = int(chan['feerate']['perkw'])
        next_feerate = '{}perkw'.format(rate * 4)

        # Initiate an RBF
        startweight = 42 + 172
        initpsbt = update_example(node=l11, method='utxopsbt', params=[FUND_CHANNEL_AMOUNT_SAT, next_feerate, startweight, prev_utxos, None, True, None, None, True])
        bump = update_example(node=l11, method='openchannel_bump', params=[chan_id, FUND_CHANNEL_AMOUNT_SAT, initpsbt['psbt'], next_feerate])

        update_example(node=l11, method='openchannel_abort', params={'channel_id': chan_id})
        bump = update_example(node=l11, method='openchannel_bump', params={'channel_id': chan_id, 'amount': FUND_CHANNEL_AMOUNT_SAT, 'initialpsbt': initpsbt['psbt'], 'funding_feerate': next_feerate})
        update = update_example(node=l11, method='openchannel_update', params={'channel_id': chan_id, 'psbt': bump['psbt']})
        signed = update_example(node=l11, method='signpsbt', params={'psbt': update['psbt']})
        update_example(node=l11, method='openchannel_signed', params={'channel_id': chan_id, 'signed_psbt': signed['signed_psbt']})

        # 5x the feerate to beat the min-relay fee
        chan = only_one(l11.rpc.listpeerchannels(l12.info['id'])['channels'])
        rate = int(chan['feerate']['perkw'])
        next_feerate = '{}perkw'.format(rate * 5)

        # Another RBF with double the channel amount
        startweight = 42 + 172
        initpsbt = update_example(node=l11, method='utxopsbt', params={'satoshi': FUND_CHANNEL_AMOUNT_SAT * 2, 'feerate': next_feerate, 'startweight': startweight, 'utxos': prev_utxos, 'reservedok': True, 'excess_as_change': True})
        bump = update_example(node=l11, method='openchannel_bump', params=[chan_id, FUND_CHANNEL_AMOUNT_SAT * 2, initpsbt['psbt'], next_feerate])
        update = update_example(node=l11, method='openchannel_update', params=[chan_id, bump['psbt']])
        signed_psbt = update_example(node=l11, method='signpsbt', params=[update['psbt']])['signed_psbt']
        update_example(node=l11, method='openchannel_signed', params=[chan_id, signed_psbt])

        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l11])
        l11.daemon.wait_for_log(' to CHANNELD_NORMAL')

        # Fundpsbt, channelopen init, abort, unreserve
        psbt_init = update_example(node=l11, method='fundpsbt', params={'satoshi': FUND_CHANNEL_AMOUNT_SAT, 'feerate': '253perkw', 'startweight': 250, 'reserve': 0})
        start = update_example(node=l11, method='openchannel_init', params={'id': l12.info['id'], 'amount': FUND_CHANNEL_AMOUNT_SAT, 'initialpsbt': psbt_init['psbt']})
        l11.rpc.openchannel_abort(start['channel_id'])
        update_example(node=l11, method='unreserveinputs', params={'psbt': psbt_init['psbt'], 'reserve': 200})

        psbt_init = update_example(node=l11, method='fundpsbt', params={'satoshi': FUND_CHANNEL_AMOUNT_SAT // 2, 'feerate': 'urgent', 'startweight': 166, 'reserve': 0, 'excess_as_change': True, 'min_witness_weight': 110})
        start = update_example(node=l11, method='openchannel_init', params=[l12.info['id'], FUND_CHANNEL_AMOUNT_SAT // 2, psbt_init['psbt']])
        l11.rpc.openchannel_abort(start['channel_id'])
        update_example(node=l11, method='unreserveinputs', params=[psbt_init['psbt']])

        # Reserveinputs
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l11])
        outputs = l11.rpc.listfunds()['outputs']
        psbt_1 = bitcoind.rpc.createpsbt([{'txid': outputs[0]['txid'], 'vout': outputs[0]['output']}], [])
        update_example(node=l11, method='reserveinputs', params={'psbt': psbt_1})
        l11.rpc.unreserveinputs(psbt_1)
        psbt_2 = bitcoind.rpc.createpsbt([{'txid': outputs[1]['txid'], 'vout': outputs[1]['output']}], [])
        update_example(node=l11, method='reserveinputs', params={'psbt': psbt_2})
        l11.rpc.unreserveinputs(psbt_2)

        # Multifundchannel 1
        l3.rpc.connect(l5.info['id'], 'localhost', l5.port)
        l4.rpc.connect(l1.info['id'], 'localhost', l1.port)
        c35res = update_example(node=l3, method='fundchannel', params={'id': l5.info['id'], 'amount': FUND_CHANNEL_AMOUNT_SAT, 'announce': True})
        outputs = l4.rpc.listfunds()['outputs']
        utxo = f"{outputs[0]['txid']}:{outputs[0]['output']}"
        c41res = update_example(node=l4, method='fundchannel',
                                params={'id': l1.info['id'], 'amount': 'all', 'feerate': 'normal', 'push_msat': 100000, 'utxos': [utxo]},
                                description=[f'This example shows how to to open new channel with peer {l1.info["id"]} from one whole utxo {utxo} (you can use **listfunds** command to get txid and vout):'])
        # Close newly funded channels to bring the setup back to initial state
        l3.rpc.close(c35res['channel_id'])
        print(f'c41res: {c41res}')
        l4.rpc.close(c41res['channel_id'])
        l3.rpc.disconnect(l5.info['id'], True)
        l4.rpc.disconnect(l1.info['id'], True)

        # Multifundchannel 2
        l1.fundwallet(10**8)
        l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
        l1.rpc.connect(l4.info['id'], 'localhost', l4.port)
        l1.rpc.connect(l5.info['id'], 'localhost', l5.port)
        multifund_res1 = update_example(node=l1, method='multifundchannel', params={
            'destinations':
            [
                {
                    'id': f'{l3.info["id"]}@127.0.0.1:{l3.port}',
                    'amount': '20000sat'
                },
                {
                    'id': f'{l4.info["id"]}@127.0.0.1:{l4.port}',
                    'amount': '0.0003btc'
                },
                {
                    'id': f'{l5.info["id"]}@127.0.0.1:{l5.port}',
                    'amount': 'all'
                }
            ],
            'feerate': '10000perkw',
            'commitment_feerate': '2000perkw'
        }, description=[
            'This example opens three channels at once, with amounts 20,000 sats, 30,000 sats',
            'and the final channel using all remaining funds (actually, capped at 16,777,215 sats',
            'because large-channels is not enabled):'
        ])
        for channel in multifund_res1['channel_ids']:
            l1.rpc.close(channel['channel_id'])
        l1.fundwallet(10**8)
        multifund_res2 = update_example(node=l1, method='multifundchannel', params={
            'destinations':
            [
                {
                    'id': f'03a389b3a2f7aa6f9f4ccc19f2bd7a2eba83596699e86b715caaaa147fc37f3144@127.0.0.1:{l3.port}',
                    'amount': 50000
                },
                {
                    'id': f'{l4.info["id"]}@127.0.0.1:{l4.port}',
                    'amount': 50000
                },
                {
                    'id': f'{l1.info["id"]}@127.0.0.1:{l1.port}',
                    'amount': 50000
                }
            ], 'minchannels': 1
        })
        # Close newly funded channels to bring the setup back to initial state
        for channel in multifund_res2['channel_ids']:
            l1.rpc.close(channel['channel_id'])
        l1.rpc.disconnect(l3.info['id'], True)
        l1.rpc.disconnect(l4.info['id'], True)
        l1.rpc.disconnect(l5.info['id'], True)
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l1, l3, l4, l5])
        logger.info('Channels Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating fundchannel and openchannel examples: {e}')


def generate_autoclean_delete_examples(l1, l2, l3, l4, l5, c12, c23):
    """Records autoclean and delete examples"""
    try:
        logger.info('Auto-clean and Delete Start...')
        global FUND_CHANNEL_AMOUNT_SAT
        l2.rpc.close(l5.info['id'])
        update_example(node=l2, method='dev-forget-channel', params={'id': l5.info['id']}, description=[f'Forget a channel by peer pubkey when only one channel exists with the peer:'])

        # Create invoices for delpay and delinvoice examples
        inv_l35 = l3.rpc.invoice('50000sat', 'lbl_l35', 'l35 description')
        inv_l36 = l3.rpc.invoice('50000sat', 'lbl_l36', 'l36 description')
        inv_l37 = l3.rpc.invoice('50000sat', 'lbl_l37', 'l37 description')

        # For MPP payment from l1 to l4; will use for delpay groupdid and partid example
        inv_l41 = l4.rpc.invoice('5000sat', 'lbl_l41', 'l41 description')
        l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
        c24, _ = l2.fundchannel(l4, FUND_CHANNEL_AMOUNT_SAT)
        l2.rpc.pay(l4.rpc.invoice(500000000, 'lbl balance l2 to l4', 'description send some sats l2 to l4')['bolt11'])
        # Create two routes; l1->l2->l3->l4 and l1->l2->l4
        route_l1_l4 = l1.rpc.getroute(l4.info['id'], '4000sat', 1)['route']
        route_l1_l2_l4 = [{'amount_msat': '1000sat', 'id': l2.info['id'], 'delay': 5, 'channel': c12},
                          {'amount_msat': '1000sat', 'id': l4.info['id'], 'delay': 5, 'channel': c24}]
        l1.rpc.sendpay(route_l1_l4, inv_l41['payment_hash'], amount_msat='5000sat', groupid=1, partid=1, payment_secret=inv_l41['payment_secret'])
        l1.rpc.sendpay(route_l1_l2_l4, inv_l41['payment_hash'], amount_msat='5000sat', groupid=1, partid=2, payment_secret=inv_l41['payment_secret'])
        # Close l2->l4 for initial state
        l2.rpc.close(l4.info['id'])
        l2.rpc.disconnect(l4.info['id'], True)

        # Delinvoice
        l1.rpc.pay(inv_l35['bolt11'])
        l1.rpc.pay(inv_l37['bolt11'])
        update_example(node=l3, method='delinvoice', params={'label': 'lbl_l36', 'status': 'unpaid'})

        # invoice already deleted, pay will fail; used for delpay failed example
        with pytest.raises(RpcError):
            l1.rpc.pay(inv_l36['bolt11'])

        listsendpays_l1 = l1.rpc.listsendpays()['payments']
        sendpay_g1_p1 = next((x for x in listsendpays_l1 if 'groupid' in x and x['groupid'] == 1 and 'partid' in x and x['partid'] == 2), None)
        update_example(node=l1, method='delpay', params={'payment_hash': listsendpays_l1[0]['payment_hash'], 'status': 'complete'})
        update_example(node=l1, method='delpay', params=[listsendpays_l1[-1]['payment_hash'], listsendpays_l1[-1]['status']])
        update_example(node=l1, method='delpay', params={'payment_hash': sendpay_g1_p1['payment_hash'], 'status': sendpay_g1_p1['status'], 'groupid': 1, 'partid': 2})
        update_example(node=l3, method='delinvoice', params={'label': 'lbl_l37', 'status': 'paid', 'desconly': True})

        # Delforward
        failed_forwards = l2.rpc.listforwards('failed')['forwards']
        local_failed_forwards = l2.rpc.listforwards('local_failed')['forwards']
        if len(local_failed_forwards) > 0 and 'in_htlc_id' in local_failed_forwards[0]:
            update_example(node=l2, method='delforward', params={'in_channel': c12, 'in_htlc_id': local_failed_forwards[0]['in_htlc_id'], 'status': 'local_failed'})
        if len(failed_forwards) > 0 and 'in_htlc_id' in failed_forwards[0]:
            update_example(node=l2, method='delforward', params=[c12, failed_forwards[0]['in_htlc_id'], 'failed'])
        update_example(node=l2, method='dev-forget-channel', params={'id': l3.info['id'], 'short_channel_id': c23, 'force': True}, description=[f'Forget a channel by short channel id when peer has multiple channels:'])

        # Autoclean
        update_example(node=l2, method='autoclean-once', params=['failedpays', 1])
        update_example(node=l2, method='autoclean-once', params=['succeededpays', 1])
        update_example(node=l2, method='autoclean-status', params={'subsystem': 'expiredinvoices'})
        update_example(node=l2, method='autoclean-status', params={})
        logger.info('Auto-clean and Delete Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating autoclean and delete examples: {e}')


def generate_backup_recovery_examples(node_factory, l4, l5, l6):
    """Node backup and recovery examples"""
    try:
        logger.info('Backup and Recovery Start...')

        # New node l13 used for recover example
        l13 = node_factory.get_node()

        update_example(node=l5, method='makesecret', params=['73636220736563726574'])
        update_example(node=l5, method='makesecret', params={'string': 'scb secret'})
        update_example(node=l4, method='emergencyrecover', params={})
        backup_l4 = update_example(node=l4, method='staticbackup', params={})

        # Recover channels
        l4.stop()
        os.unlink(os.path.join(l4.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3'))
        l4.start()
        time.sleep(1)
        update_example(node=l4, method='recoverchannel', params=[backup_l4['scb']])

        # Emergency recover
        l5.stop()
        os.unlink(os.path.join(l5.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3'))
        l5.start()
        time.sleep(1)
        update_example(node=l5, method='emergencyrecover', params={})

        # Recover
        def get_hsm_secret(n):
            """Returns codex32 and hex"""
            try:
                hsmfile = os.path.join(n.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
                codex32 = subprocess.check_output(["tools/hsmtool", "getcodexsecret", hsmfile, "leet"]).decode('utf-8').strip()
                with open(hsmfile, "rb") as f:
                    hexhsm = f.read().hex()
                return codex32, hexhsm
            except Exception as e:
                logger.error(f'Error in getting hsm secret: {e}')

        _, l6hex = get_hsm_secret(l6)
        l13codex32, _ = get_hsm_secret(l13)
        update_example(node=l6, method='recover', params={'hsmsecret': l6hex})
        update_example(node=l13, method='recover', params={'hsmsecret': l13codex32})
        logger.info('Backup and Recovery Done!')
    except TaskFinished:
        raise
    except Exception as e:
        logger.error(f'Error in generating backup and recovery examples: {e}')


@unittest.skipIf(GENERATE_EXAMPLES is not True, 'Generates examples for doc/schema/lightning-*.json files.')
def test_generate_examples(node_factory, bitcoind, executor):
    """Re-generates examples for doc/schema/lightning-*.json files"""
    try:
        global ALL_METHOD_NAMES, ALL_RPC_EXAMPLES, REGENERATING_RPCS, RPCS_STATUS

        def list_all_examples():
            """list all methods used in 'update_example' calls to ensure that all methods are covered"""
            try:
                global REGENERATING_RPCS
                methods = {}
                file_path = os.path.abspath(__file__)

                # Parse and traverse this file's content to list all methods & file names
                with open(file_path, "r") as file:
                    file_content = file.read()
                tree = ast.parse(file_content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'update_example':
                        for keyword in node.keywords:
                            if (keyword.arg == 'method' and isinstance(keyword.value, ast.Str)) or (keyword.arg == 'filename' and isinstance(keyword.value, ast.Str)):
                                method_name = keyword.value.s
                                if method_name not in methods:
                                    methods[method_name] = {'method': method_name, 'num_examples': 1, 'executed': 0}
                                else:
                                    methods[method_name]['num_examples'] += 1
                return list(methods.values())
            except Exception as e:
                logger.error(f'Error in listing all examples: {e}')

        def list_missing_examples():
            """Checks for missing example file or example & log an error if missing."""
            try:
                global ALL_METHOD_NAMES
                for file_name in os.listdir('doc/schemas'):
                    if not file_name.endswith('.json'):
                        continue
                    file_name_str = str(file_name).replace('lightning-', '').replace('.json', '')
                    # Log an error if the method is not in the list
                    if file_name_str not in ALL_METHOD_NAMES:
                        logger.error(f'Missing File or Example {file_name_str}.')
            except Exception as e:
                logger.error(f'Error in listing missing examples: {e}')

        def clear_existing_examples():
            """Clear existing examples in JSON files to regenerate them later"""
            global REGENERATING_RPCS
            for rpc in REGENERATING_RPCS:
                try:
                    global CWD
                    file_path = os.path.join(CWD, 'doc', 'schemas', f'lightning-{rpc}.json')
                    with open(file_path, 'r+', encoding='utf-8') as file:
                        data = json.load(file)
                        # Deletes the 'examples' key corresponding to the method's file
                        if 'examples' in data:
                            del data['examples']
                            file.seek(0)
                            json.dump(data, file, indent=2, ensure_ascii=False)
                            file.write('\n')
                            file.truncate()
                except FileNotFoundError as fnf_error:
                    logger.error(f'File not found error {fnf_error} for {file_path}')
                except Exception as e:
                    logger.error(f'Error saving example in file {file_path}: {e}')
            logger.info(f'Cleared Examples: {REGENERATING_RPCS}')
            return None

        ALL_RPC_EXAMPLES = list_all_examples()
        ALL_METHOD_NAMES = [example['method'] for example in ALL_RPC_EXAMPLES]
        logger.info(f'This test can reproduce examples for {len(ALL_RPC_EXAMPLES)} methods: {ALL_METHOD_NAMES}')
        REGENERATING_RPCS = [rpc.strip() for rpc in os.getenv("REGENERATE").split(',')] if os.getenv("REGENERATE") else ALL_METHOD_NAMES
        logger.info(f'Regenerating examples for: {REGENERATING_RPCS}')
        RPCS_STATUS = [False] * len(REGENERATING_RPCS)
        list_missing_examples()
        clear_existing_examples()
        l1, l2, l3, l4, l5, l6, c12, c23, c25, c34, c23res = setup_test_nodes(node_factory, bitcoind)
        inv_l11, inv_l21, inv_l22, inv_l31, inv_l32, inv_l34 = generate_transactions_examples(l1, l2, l3, l4, l5, c25, bitcoind)
        rune_l21 = generate_runes_examples(l1, l2, l3)
        generate_datastore_examples(l2)
        generate_bookkeeper_examples(l2, l3, c23res['channel_id'])
        generate_offers_renepay_examples(l1, l2, inv_l21, inv_l34)
        generate_list_examples(l1, l2, l3, c12, c23, inv_l31, inv_l32)
        generate_wait_examples(l1, l2, bitcoind, executor)
        generate_utils_examples(l1, l2, l3, l4, l5, l6, c23, c34, inv_l11, inv_l22, rune_l21, bitcoind)
        generate_splice_examples(node_factory, bitcoind)
        generate_channels_examples(node_factory, bitcoind, l1, l3, l4, l5)
        generate_autoclean_delete_examples(l1, l2, l3, l4, l5, c12, c23)
        generate_backup_recovery_examples(node_factory, l4, l5, l6)
        logger.info('All examples generated successfully!')
    except TaskFinished as m:
        logger.info(m)
    except Exception as e:
        # FIXME: The test passes but with flaky errors:
        # 1: plugin-bcliBROKEN: bitcoin-cli -regtest -datadir=/tmp/ltests-65999628/test_generate_examples_1/lightning-6/ -rpcclienttimeout=60 -rpcport=57425 -rpcuser=... -stdinrpcpass getblockhash 159 exited 1 (after 60 other errors)
        # 'Error: Specified data directory \"/tmp/ltests-65999628/test_generate_examples_1/lightning-6/\" does not exist.\n'; we have been retrying command for --bitcoin-retry-timeout=60 seconds; bitcoind setup or our --bitcoin-* configs broken?
        # 2: Node /tmp/ltests-joqzs3fy/test_generate_examples_1/lightning-3/ has memory leaks: [{"subdaemon": "lightningd"}]
        logger.error(e)
