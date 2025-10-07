# NOTE: For detailed documentation, refer to https://docs.corelightning.org/docs/writing-json-schemas.
# NOTE: Set the test `TIMEOUT` to greater than 3 seconds to prevent failures caused by waiting on the bitcoind response.
# The `dev-bitcoind-poll` interval is 3 seconds, so a shorter timeout may result in test failures.
# NOTE: Different nodes are selected to record examples based on data availability, quality, and volume.
# For example, node `l1` is used to capture examples for `listsendpays`, whereas node `l2` is utilized for `listforwards`.


from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError, Millisatoshi  # type: ignore
from pyln.testing.utils import GENERATE_EXAMPLES
from utils import only_one, mine_funding_to_announce, sync_blockheight, wait_for, first_scid, serialize_payload_tlv, serialize_payload_final_tlv
import socket
import sys
import os
import time
import pytest
import unittest
import json
import logging
import ast
import subprocess

CWD = os.getcwd()
CLN_VERSION = 'v'
with open(os.path.join('.version'), 'r') as f:
    CLN_VERSION = CLN_VERSION + f.read().strip()

FUND_WALLET_AMOUNT_SAT = 200000000
FUND_CHANNEL_AMOUNT_SAT = 10**6
REGENERATING_RPCS = []
ALL_RPC_EXAMPLES = {}
EXAMPLES_JSON = {}
LOG_FILE = './tests/autogenerate-examples-status.log'
IGNORE_RPCS_LIST = ['dev-splice', 'reckless', 'sql-template']
BASE_PORTNUM = 30000

if os.path.exists(LOG_FILE):
    open(LOG_FILE, 'w').close()
logger = logging.getLogger(__name__)


class MissingExampleError(Exception):
    pass


def check_ports(portrange):
    for port in portrange:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                logger.error(f'Port {port} in use!')
                raise


def update_examples_in_schema_files():
    """Update examples in JSON schema files"""
    try:
        updated_examples = {}
        for method, method_examples in EXAMPLES_JSON.items():
            try:
                file_path = os.path.join(CWD, 'doc', 'schemas', f'{method}.json') if method != 'sql' else os.path.join(CWD, 'doc', 'schemas', f'{method}-template.json')
                logger.info(f'Updating examples for {method} in file {file_path}')
                with open(file_path, 'r+', encoding='utf-8') as file:
                    data = json.load(file)
                    updated_examples[method] = method_examples['examples']
                    data['examples'] = updated_examples[method]
                    file.seek(0)
                    json.dump(data, file, indent=2, ensure_ascii=False)
                    file.write('\n')
                    file.truncate()
            except FileNotFoundError as fnf_error:
                logger.error(f'File not found error {fnf_error} for {file_path}')
                raise
            except Exception as e:
                logger.error(f'Error saving example in file {file_path}: {e}')
                raise
    except Exception as e:
        logger.error(f'Error updating examples in schema files: {e}')
        raise

    logger.info(f'Updated All Examples in Schema Files!')
    return None


def update_example(node, method, params, response=None, description=None):
    """Add example request, response and other details in json array for future use"""
    method_examples = EXAMPLES_JSON.get(method, {'examples': []})
    method_id = len(method_examples['examples']) + 1
    req = {
        'id': f'example:{method}#{method_id}',
        'method': method,
        'params': params
    }
    logger.info(f'Method \'{method}\', Params {params}')
    # Execute the RPC call and get the response
    if response is None:
        response = node.rpc.call(method, params)
    logger.info(f'{method} response: {response}')
    # Return response without updating the file because user doesn't want to update the example
    # Executing the method and returning the response is useful for further example updates
    if method not in REGENERATING_RPCS:
        return response
    else:
        method_examples['examples'].append({'request': req, 'response': response} if description is None else {'description': description, 'request': req, 'response': response})
        EXAMPLES_JSON[method] = method_examples
    logger.info(f'Updated {method}#{method_id} example json')
    return response


def setup_test_nodes(node_factory, bitcoind, regenerate_blockchain):
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
        options = [
            {
                'experimental-dual-fund': None,
                'may_reconnect': True,
                'dev-hsmd-no-preapprove-check': None,
                'dev-no-plugin-checksum': None,
                'dev-no-version-checks': None,
                'allow-deprecated-apis': True,
                'allow_bad_gossip': True,
                'log-level': 'debug',
                'broken_log': '.*',
                'dev-bitcoind-poll': 3,    # Default 1; increased to avoid rpc failures
                'no_entropy': True,
                'base_port': BASE_PORTNUM,
            }.copy()
            for i in range(6)
        ]
        l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=options)
        # Upgrade wallet
        # Write the data/p2sh_wallet_hsm_secret to the hsm_path, so node can spend funds at p2sh_wrapped_addr
        p2sh_wrapped_addr = '2N2V4ee2vMkiXe5FSkRqFjQhiS9hKqNytv3'
        update_example(node=l1, method='upgradewallet', params={})
        txid = bitcoind.send_and_mine_block(p2sh_wrapped_addr, 20000000)
        sync_blockheight(bitcoind, [l1, l2, l3, l4, l5, l6])
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
        c12, c12res = l1.fundchannel(l2, FUND_CHANNEL_AMOUNT_SAT)
        sync_blockheight(bitcoind, [l1, l2, l3, l4, l5, l6])
        c23, c23res = l2.fundchannel(l3, FUND_CHANNEL_AMOUNT_SAT)
        sync_blockheight(bitcoind, [l1, l2, l3, l4, l5, l6])
        c34, c34res = l3.fundchannel(l4, FUND_CHANNEL_AMOUNT_SAT)
        sync_blockheight(bitcoind, [l1, l2, l3, l4, l5, l6])
        c25, c25res = l2.fundchannel(l5, announce_channel=False)
        mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])
        sync_blockheight(bitcoind, [l1, l2, l3, l4, l5, l6])
        l1.wait_channel_active(c12)
        l1.wait_channel_active(c23)
        l1.wait_channel_active(c34)
        # Balance these newly opened channels
        l1.rpc.pay(l2.rpc.invoice('500000sat', 'lbl balance l1 to l2', 'description send some sats l1 to l2')['bolt11'])
        l2.rpc.pay(l3.rpc.invoice('500000sat', 'lbl balance l2 to l3', 'description send some sats l2 to l3')['bolt11'])
        l2.rpc.pay(l5.rpc.invoice('500000sat', 'lbl balance l2 to l5', 'description send some sats l2 to l5')['bolt11'])
        l3.rpc.pay(l4.rpc.invoice('500000sat', 'lbl balance l3 to l4', 'description send some sats l3 to l4')['bolt11'])
        return l1, l2, l3, l4, l5, l6, c12, c23, c25
    except Exception as e:
        logger.error(f'Error in setting up nodes: {e}')
        raise


def generate_transactions_examples(l1, l2, l3, l4, l5, c25, bitcoind):
    """Generate examples for various transactions and forwards"""
    try:
        logger.info('Simple Transactions Start...')
        # Simple Transactions by creating invoices, paying invoices, keysends
        inv_l31 = update_example(node=l3, method='invoice', params={'amount_msat': 10**4, 'label': 'lbl_l31', 'description': 'Invoice description l31'})
        route_l1_l3 = update_example(node=l1, method='getroute', params={'id': l3.info['id'], 'amount_msat': 10**4, 'riskfactor': 1})['route']
        inv_l32 = update_example(node=l3, method='invoice', params={'amount_msat': '50000msat', 'label': 'lbl_l32', 'description': 'l32 description'})
        update_example(node=l2, method='getroute', params={'id': l4.info['id'], 'amount_msat': 500000, 'riskfactor': 10, 'cltv': 9})['route']
        update_example(node=l1, method='sendpay', params={'route': route_l1_l3, 'payment_hash': inv_l31['payment_hash'], 'payment_secret': inv_l31['payment_secret']})
        update_example(node=l1, method='waitsendpay', params={'payment_hash': inv_l31['payment_hash']})
        update_example(node=l1, method='keysend', params={'destination': l3.info['id'], 'amount_msat': 10000})
        update_example(node=l1, method='keysend', params={'destination': l4.info['id'], 'amount_msat': 10000000, 'extratlvs': {'133773310': '68656c6c6f776f726c64', '133773312': '66696c7465726d65'}})
        scid = only_one([channel for channel in l2.rpc.listpeerchannels()['channels'] if channel['peer_id'] == l3.info['id']])['alias']['remote']
        routehints = [[{
            'scid': scid,
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

        inv_l41 = l4.rpc.invoice('10000msat', 'test_xpay_simple', 'test_xpay_simple bolt11')
        update_example(node=l1, method='xpay', params=[inv_l41['bolt11']])
        offer_l11 = l1.rpc.offer('any')
        inv_l14 = l1.rpc.fetchinvoice(offer_l11['bolt12'], '1000msat')
        update_example(node=l1, method='xpay', params={'invstring': inv_l14['invoice']})

        update_example(node=l1, method='injectonionmessage', params={'message': '0002cb7cd2001e3c670d64135542dcefdf4a3f590eb142cee9277b317848471906caeabe4afeae7f4e31f6ca9c119b643d5369c5e55f892f205469a185f750697124a2bb7ccea1245ec12d76340bcf7371ba6d1c9ddfe09b4153fce524417c14a594fdbb5e7c698a5daffe77db946727a38711be2ecdebdd347d2a9f990810f2795b3c39b871d7c72a11534bd388ca2517630263d96d8cc72d146bae800638066175c85a8e8665160ea332ed7d27efc31c960604d61c3f83801c25cbb69ae3962c2ef13b1fa9adc8dcbe3dc8d9a5e27ff5669e076b02cafef8f2c88fc548e03642180d57606386ad6ce27640339747d40f26eb5b9e93881fc8c16d5896122032b64bb5f1e4be6f41f5fa4dbd7851989aeccd80b2d5f6f25427f171964146185a8eaa57891d91e49a4d378743231e19edd5994c3118c9a415958a5d9524a6ecc78c0205f5c0059a7fbcf1abad706a189b712476d112521c9a4650d0ff09890536acae755a2b07d00811044df28b288d3dc2d5ae3f8bf3cf7a2950e2167105dfad0fb8398ef08f36abcdb1bfd6aca3241c33810f0750f35bdfb7c60b1759275b7704ab1bc8f3ea375b3588eab10e4f948f12fe0a3c77b67bebeedbcced1de0f0715f9959e5497cda5f8f6ab76c15b3dcc99956465de1bf2855338930650f8e8e8c391d9bb8950125dd60d8289dade0556d9dc443761983e26adcc223412b756e2fd9ad64022859b6cab20e8ffc3cf39ae6045b2c3338b1145ee3719a098e58c425db764d7f9a5034dbb730c20202f79bc3c53fab78ecd530aa0e8f7698c9ea53cb96dc9c639282c362d31177c5b81979f46f2db6090b8e171db47287523f28c462e35ef489b51426387f2709c342083968153b5f8a51cd5716b38106bb0f21c5ccfc28dd7c74b71c8367ae8ca348f66a7996bbc535076a1f65d9109658ec042257ca7523488fb1807dc8bec42739ccae066739cf58083b4e2c65e52e1747a6ec2aa26338bb6f2c3195a2b160e26dec70a2cfde269fa7c10c45d346a8bcc313bb618324edadc0291d15f4dc00ca3a7ad7131045fdf6978ba52178f4699525efcb8d96561630e2f28eaa97c66c38c66301b6c6f0124b550db620b09f35b9d45d1441cab7d93be5e3c39b9becfab7f8d05dd3a7a6e27a1d3f23f1dd01e967f5206600619f75439181848f7f4148216c11314b4eaf64c28c268ad4b33ea821d57728e9a9e9e1b6c4bcf35d14958295fc5f92bd6846f33c46f5fa20f569b25bc916b94e554f27a37448f873497e13baef8c740a7587828cc4136dd21b8584e6983e376e91663f8f91559637738b400fb49940fc2df299dfd448604b63c2f5d1f1ec023636f3baf2be5730364afd38191726a7c0d9477b1f231da4d707aabc6ad8036488181dbdb16b48500f2333036629004504d3524f87ece6afb04c4ba03ea6fce069e98b1ab7bf51f237d7c0f40756744dd703c6023b6461b90730f701404e8dddfaff40a9a60e670be7729556241fc9cc8727a586e38b71616bff8772c873b37d920d51a6ad31219a24b12f268545e2cfeb9e662236ab639fd4ecf865612678471ff7b320c934a13ca1f2587fc6a90f839c3c81c0ff84b51330820431418918e8501844893b53c1e0de46d51a64cb769974a996c58ff06683ebdc46fd4bb8e857cecebab785a351c64fd486fb648d25936cb09327b70d22c243035d4343fa3d2d148e2df5cd928010e34ae42b0333e698142050d9405b39f3aa69cecf8a388afbc7f199077b911cb829480f0952966956fe57d815f0d2467f7b28af11f8820645b601c0e1ad72a4684ebc60287d23ec3502f4c65ca44f5a4a0d79e3a5718cd23e7538cb35c57673fb9a1173e5526e767768117c7fefc2e3718f44f790b27e61995fecc6aef05107e75355be301ebe1500c147bb655a159f',
                                                                     'path_key': '03ccf3faa19e8d124f27d495e3359f4002a6622b9a02df9a51b609826d354cda52'})

        blockheight = l1.rpc.getinfo()['blockheight']
        amt = 10**3
        route = l1.rpc.getroute(l4.info['id'], amt, 10)['route']
        inv = l4.rpc.invoice(amt, "lbl l4", "desc l4")
        first_hop = route[0]
        sendonion_hops = []
        i = 1
        for h, n in zip(route[:-1], route[1:]):
            sendonion_hops.append({'pubkey': h['id'], 'payload': serialize_payload_tlv(amt, 18 + 6, n['channel'], blockheight).hex()})
            i += 1
        sendonion_hops.append({'pubkey': route[-1]['id'], 'payload': serialize_payload_final_tlv(amt, 18, amt, blockheight, inv['payment_secret']).hex()})
        onion_res1 = update_example(node=l1, method='createonion', params={'hops': sendonion_hops, 'assocdata': inv['payment_hash']})
        update_example(node=l1, method='createonion', params={'hops': sendonion_hops, 'assocdata': inv['payment_hash'], 'session_key': '41' * 32})
        update_example(node=l1, method='sendonion', params={'onion': onion_res1['onion'], 'first_hop': first_hop, 'payment_hash': inv['payment_hash']})

        # Close channels examples
        update_example(node=l2, method='close', params={'id': l3.info['id'], 'unilateraltimeout': 1})
        address_l41 = l4.rpc.newaddr()
        update_example(node=l3, method='close', params={'id': l4.info['id'], 'destination': address_l41['bech32']})
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l1, l2, l3, l4])

        # Channel 2 to 3 is closed, l1->l3 payment will fail where `failed` forward will be saved on l2
        l1.rpc.sendpay(route_l1_l3, inv_l34['payment_hash'], payment_secret=inv_l34['payment_secret'])
        with pytest.raises(RpcError):
            l1.rpc.waitsendpay(inv_l34['payment_hash'])

        # Reopen channels for further examples
        c23_2, c23res2 = l2.fundchannel(l3, FUND_CHANNEL_AMOUNT_SAT)
        c34_2, c34res2 = l3.fundchannel(l4, FUND_CHANNEL_AMOUNT_SAT)
        mine_funding_to_announce(bitcoind, [l3, l4])
        l2.wait_channel_active(c23_2)
        update_example(node=l2, method='setchannel', params={'id': c23_2, 'ignorefeelimits': True})
        update_example(node=l2, method='setchannel', params={'id': c25, 'feebase': 4000, 'feeppm': 300, 'enforcedelay': 0})

        # Some more invoices for signing and preapproving
        inv_l12 = l1.rpc.invoice(1000, 'label inv_l12', 'description inv_l12')
        inv_l24 = l2.rpc.invoice(123000, 'label inv_l24', 'description inv_l24', 3600)
        inv_l25 = l2.rpc.invoice(124000, 'label inv_l25', 'description inv_l25', 3600)
        inv_l26 = l2.rpc.invoice(125000, 'label inv_l26', 'description inv_l26', 3600)
        update_example(node=l2, method='signinvoice', params={'invstring': inv_l12['bolt11']})
        update_example(node=l3, method='signinvoice', params=[inv_l26['bolt11']])
        update_example(node=l1, method='preapprovekeysend', params={'destination': l2.info['id'], 'payment_hash': '00' * 32, 'amount_msat': 1000})
        update_example(node=l5, method='preapprovekeysend', params=[l5.info['id'], '01' * 32, 2000])
        update_example(node=l1, method='preapproveinvoice', params={'bolt11': inv_l24['bolt11']})
        update_example(node=l1, method='preapproveinvoice', params=[inv_l25['bolt11']])
        inv_req = update_example(node=l2, method='invoicerequest', params={'amount': 1000000, 'description': 'Simple test'})
        update_example(node=l1, method='sendinvoice', params={'invreq': inv_req['bolt12'], 'label': 'test sendinvoice'})
        inv_l13 = l1.rpc.invoice(amount_msat=100000, label='lbl_l13', description='l13 description', preimage='01' * 32)
        update_example(node=l2, method='createinvoice', params={'invstring': inv_l13['bolt11'], 'label': 'lbl_l13', 'preimage': '01' * 32})
        inv_l27 = l2.rpc.invoice(amt, 'test_injectpaymentonion1', 'test injectpaymentonion1 description')
        injectpaymentonion_hops = [
            {'pubkey': l1.info['id'],
             'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
            {'pubkey': l2.info['id'],
             'payload': serialize_payload_final_tlv(1000, 18, 1000, blockheight, inv_l27['payment_secret']).hex()}]
        onion_res3 = l1.rpc.createonion(hops=injectpaymentonion_hops, assocdata=inv_l27['payment_hash'])
        update_example(node=l1, method='injectpaymentonion', params={
            'onion': onion_res3['onion'],
            'payment_hash': inv_l27['payment_hash'],
            'amount_msat': 1000,
            'cltv_expiry': blockheight + 18 + 6,
            'partid': 1,
            'groupid': 0})
        update_example(node=l1, method='fetchbip353', params={'address': 'send.some@satsto.me'}, description=['Example of fetching BIP-353 payment details.'])
        logger.info('Simple Transactions Done!')
        return c23_2, c23res2, c34_2, inv_l11, inv_l21, inv_l22, inv_l31, inv_l32, inv_l34
    except Exception as e:
        logger.error(f'Error in generating transactions examples: {e}')
        raise


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
                                               '2: `[\'method/listdatastore\']`: But not listdatastore: that contains sensitive stuff!'])
        update_example(node=l2, method='createrune', params={'rune': rune_l21['rune'], 'restrictions': [['method^list', 'method^get', 'method=summary'], ['method/listdatastore']]}, description=['We can do the same manually (readonly), like so:'])
        rune_l23 = update_example(node=l2, method='createrune', params={'restrictions': [[f'id^{trimmed_id}'], ['method=listpeers']]}, description=[f'This will allow the rune to be used for id starting with {trimmed_id}, and for the method listpeers:'])
        rune_l24 = update_example(node=l2, method='createrune', params={'restrictions': [['method=pay'], ['pnameamountmsat<10000']]}, description=['This will allow the rune to be used for the method pay, and for the parameter amount\\_msat to be less than 10000:'])
        update_example(node=l2, method='createrune', params={'restrictions': [[f'id={l1.info["id"]}'], ['method=listpeers'], ['pnum=1'], [f'pnameid={l1.info["id"]}', f'parr0={l1.info["id"]}']]}, description=["Let's create a rune which lets a specific peer run listpeers on themselves:"])
        rune_l25 = update_example(node=l2, method='createrune', params={'restrictions': [[f'id={l1.info["id"]}'], ['method=listpeers'], ['pnum=1'], [f'pnameid^{trimmed_id}', f'parr0^{trimmed_id}']]}, description=["This allows `listpeers` with 1 argument (`pnum=1`), which is either by name (`pnameid`), or position (`parr0`). We could shorten this in several ways: either allowing only positional or named parameters, or by testing the start of the parameters only. Here's an example which only checks the first 10 bytes of the `listpeers` parameter:"])
        update_example(node=l2, method='createrune', params=[rune_l25['rune'], [['time<"$(($(date +%s) + 24*60*60))"', 'rate=2']]], description=["Before we give this to our peer, let's add two more restrictions: that it only be usable for 24 hours from now (`time<`), and that it can only be used twice a minute (`rate=2`). `date +%s` can give us the current time in seconds:"])
        update_example(node=l2, method='createrune', params={'restrictions': [['method^list', 'method^get', 'method=summary', 'method=pay', 'method=xpay'], ['method/listdatastore'], ['method/pay', 'per=1day'], ['method/pay', 'pnameamount_msat<100000001'], ['method/xpay', 'per=1day'], ['method/xpay', 'pnameamount_msat<100000001']]},
                       description=['Now, let us create a rune with `read-only` restrictions, extended to only allow sending payments of `less than 100,000 sats per day` using either the `pay` or `xpay` method. Ideally, the condition would look something like:',
                                    '',
                                    '`[["method^list or method^get or ((method=pay or method=xpay) and per=1day and pnameamount\\_msat<100000001)"],["method/listdatastore"]]`.',
                                    '',
                                    'However, since brackets and AND conditions within OR are currently not supported for rune creation, we can restructure the conditions as follows:',
                                    '',
                                    '- method^list|method^get|method=summary|method=pay|method=xpay',
                                    '- method/listdatastore',
                                    '- method/pay|per=1day',
                                    '- method/pay|pnameamount\\_msat<100000001',
                                    '- method/xpay|per=1day',
                                    '- method/xpay|pnameamount\\_msat<100000001'])
        update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l21['rune'], 'method': 'newaddr', 'params': {'addresstype': 'p2tr'}})
        update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l23['rune'], 'method': 'listpeers', 'params': [l3.info['id']]})
        inv_l23 = l2.rpc.invoice('any', 'lbl_l23', 'l23 description')
        update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l24['rune'], 'method': 'pay', 'params': {'bolt11': inv_l23['bolt11'], 'amount_msat': 9900}})
        update_example(node=l2, method='checkrune', params={'nodeid': l2.info['id'], 'rune': rune_l22['rune'], 'method': 'listpeers', 'params': {}})
        update_example(node=l2, method='checkrune', params={'nodeid': l2.info['id'], 'rune': rune_l24['rune'], 'method': 'pay', 'params': {'amount_msat': 9999}})
        update_example(node=l2, method='showrunes', params={'rune': rune_l21['rune']})
        update_example(node=l2, method='showrunes', params={})
        update_example(node=l2, method='blacklistrune', params={'start': 1})
        update_example(node=l2, method='blacklistrune', params={'start': 0, 'end': 2})
        update_example(node=l2, method='blacklistrune', params={'start': 3, 'end': 4})
        update_example(node=l2, method='blacklistrune', params={'start': 3, 'relist': True},
                       description=['This undoes the blacklisting of rune 3 only'])

        logger.info('Runes Done!')
        return rune_l21
    except Exception as e:
        logger.error(f'Error in generating runes examples: {e}')
        raise


def generate_datastore_examples(l2):
    """Covers all datastore related examples"""
    try:
        logger.info('Datastore Start...')
        l2.rpc.datastore(key='somekey', hex='61', mode='create-or-append')
        l2.rpc.datastore(key=['test', 'name'], string='saving data to the store', mode='must-create')
        update_example(node=l2, method='datastore', params={'key': ['employee', 'index'], 'string': 'saving employee keys to the store', 'mode': 'must-create'})
        update_example(node=l2, method='datastore', params={'key': 'otherkey', 'string': 'other', 'mode': 'must-create'})
        update_example(node=l2, method='datastore', params={'key': 'otherkey', 'string': ' key: text to be appended to the otherkey', 'mode': 'must-append', 'generation': 0})
        update_example(node=l2, method='datastoreusage', params={})
        update_example(node=l2, method='datastoreusage', params={'key': ['test', 'name']})
        update_example(node=l2, method='datastoreusage', params={'key': 'otherkey'})
        update_example(node=l2, method='deldatastore', params={'key': ['test', 'name']})
        update_example(node=l2, method='deldatastore', params={'key': 'otherkey', 'generation': 1})
        logger.info('Datastore Done!')
    except Exception as e:
        logger.error(f'Error in generating datastore examples: {e}')
        raise


def generate_bookkeeper_examples(l2, l3, c23_2_chan_id):
    """Generates all bookkeeper rpc examples"""
    try:
        logger.info('Bookkeeper Start...')
        update_example(node=l2, method='funderupdate', params={})
        update_example(node=l2, method='funderupdate', params={'policy': 'fixed', 'policy_mod': '50000sat', 'min_their_funding_msat': 1000, 'per_channel_min_msat': '1000sat', 'per_channel_max_msat': '500000sat', 'fund_probability': 100, 'fuzz_percent': 0, 'leases_only': False})
        update_example(node=l2, method='bkpr-inspect', params={'account': c23_2_chan_id})
        update_example(node=l2, method='bkpr-dumpincomecsv', params=['koinly', 'koinly.csv'])
        bkpr_channelsapy_res1 = l2.rpc.bkpr_channelsapy()
        fields = [
            ('utilization_out', '3{}.7060%'),
            ('utilization_out_initial', '5{}.5591%'),
            ('utilization_in', '1{}.0027%'),
            ('utilization_in_initial', '5{}.0081%'),
            ('apy_out', '0.008{}%'),
            ('apy_out_initial', '0.012{}%'),
            ('apy_in', '0.008{}%'),
            ('apy_in_initial', '0.025{}%'),
            ('apy_total', '0.016{}%'),
            ('apy_total_initial', '0.016{}%'),
        ]
        for i, channel in enumerate(bkpr_channelsapy_res1['channels_apy']):
            for key, pattern in fields:
                if key in channel:
                    channel[key] = pattern.format(i)
        update_example(node=l2, method='bkpr-channelsapy', params={}, response=bkpr_channelsapy_res1)

        # listincome and editing descriptions
        listincome_result = l3.rpc.bkpr_listincome(consolidate_fees=False)
        invoice = next((event for event in listincome_result['income_events'] if 'payment_id' in event), None)
        utxo_event = next((event for event in listincome_result['income_events'] if 'outpoint' in event), None)
        update_example(node=l3, method='bkpr-editdescriptionbypaymentid', params={'payment_id': invoice['payment_id'], 'description': 'edited invoice description from description send some sats l2 to l3'})
        # Try to edit a payment_id that does not exist
        update_example(node=l3, method='bkpr-editdescriptionbypaymentid', params={'payment_id': 'c000' + ('01' * 30), 'description': 'edited invoice description for non existing payment id'})
        update_example(node=l3, method='bkpr-editdescriptionbyoutpoint', params={'outpoint': utxo_event['outpoint'], 'description': 'edited utxo description'})
        # Try to edit an outpoint that does not exist
        update_example(node=l3, method='bkpr-editdescriptionbyoutpoint', params={'outpoint': 'abcd' + ('02' * 30) + ':1', 'description': 'edited utxo description for non existing outpoint'})

        update_example(node=l3, method='bkpr-listbalances', params={})

        bkprlistaccountevents_res1 = l3.rpc.bkpr_listaccountevents(c23_2_chan_id)
        update_example(node=l3, method='bkpr-listaccountevents', params=[c23_2_chan_id], response=bkprlistaccountevents_res1)
        bkprlistaccountevents_res2 = l3.rpc.bkpr_listaccountevents()
        update_example(node=l3, method='bkpr-listaccountevents', params={}, response=bkprlistaccountevents_res2)
        bkprlistincome_res1 = l3.rpc.bkpr_listincome(consolidate_fees=False)
        update_example(node=l3, method='bkpr-listincome', params={'consolidate_fees': False}, response=bkprlistincome_res1)
        bkprlistincome_res2 = l3.rpc.bkpr_listincome()
        update_example(node=l3, method='bkpr-listincome', params={}, response=bkprlistincome_res2)
        logger.info('Bookkeeper Done!')
    except Exception as e:
        logger.error(f'Error in generating bookkeeper examples: {e}')
        raise


def generate_coinmvt_examples(l2):
    """Generates listchannelmoves and listchainmoves rpc examples"""
    try:
        logger.info('listcoinmoves Start...')
        update_example(node=l2, method='listchainmoves', params={})
        update_example(node=l2, method='listchainmoves', params={'index': 'created', 'start': 10})
        update_example(node=l2, method='listchannelmoves', params={})
        update_example(node=l2, method='listchannelmoves', params={'index': 'created', 'start': 10, 'limit': 2})
    except Exception as e:
        logger.error(f'Error in generating coinmoves examples: {e}')
        raise


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
        update_example(node=l2, method='enableoffer', params={'offer_id': offer_l23['offer_id']})

        # Invoice Requests
        inv_req_l1_l22 = update_example(node=l2, method='invoicerequest', params={'amount': '10000sat', 'description': 'Requesting for invoice', 'issuer': 'clightning store'})
        update_example(node=l2, method='disableinvoicerequest', params={'invreq_id': inv_req_l1_l22['invreq_id']})

        # Renepay
        update_example(node=l1, method='renepay', params={'invstring': inv_l21['bolt11'], 'amount_msat': 400000})
        update_example(node=l2, method='renepay', params={'invstring': inv_l34['bolt11']})
        update_example(node=l1, method='renepaystatus', params={'invstring': inv_l21['bolt11']})
        logger.info('Offers and Renepay Done!')
        return offer_l23, inv_req_l1_l22
    except Exception as e:
        logger.error(f'Error in generating offers or renepay examples: {e}')
        raise


def generate_askrene_examples(l1, l2, l3, c12, c23_2):
    """Generates askrene related examples"""
    try:
        logger.info('Askrene Start...')

        def direction(src, dst):
            if src < dst:
                return 0
            return 1

        direction12 = direction(l1.info['id'], l2.info['id'])
        direction23 = direction(l2.info['id'], l3.info['id'])
        scid12dir = f'{c12}/{direction12}'
        scid23dir = f'{c23_2}/{direction23}'
        update_example(node=l2, method='askrene-create-layer', params={'layer': 'test_layers'})
        update_example(node=l2, method='askrene-disable-node', params={'layer': 'test_layers', 'node': l1.info['id']})
        update_example(node=l2, method='askrene-update-channel', params=['test_layers', '0x0x1/0'])
        update_example(node=l2, method='askrene-create-channel', params={'layer': 'test_layers', 'source': l3.info['id'], 'destination': l1.info['id'], 'short_channel_id': '0x0x1', 'capacity_msat': '1000000sat'})
        update_example(node=l2, method='askrene-update-channel', params={'layer': 'test_layers', 'short_channel_id_dir': '0x0x1/0', 'htlc_minimum_msat': 100, 'htlc_maximum_msat': 900000000, 'fee_base_msat': 1, 'fee_proportional_millionths': 2, 'cltv_expiry_delta': 18})
        update_example(node=l2, method='askrene-inform-channel', params={'layer': 'test_layers', 'short_channel_id_dir': '0x0x1/1', 'amount_msat': 100000, 'inform': 'unconstrained'})
        update_example(node=l2, method='askrene-bias-channel', params={'layer': 'test_layers', 'short_channel_id_dir': scid12dir, 'bias': 1})
        update_example(node=l2, method='askrene-bias-channel', params=['test_layers', scid12dir, -5, 'bigger bias'])
        askrene_listlayers_res1 = update_example(node=l2, method='askrene-listlayers', params=['test_layers'])
        update_example(node=l2, method='askrene-listlayers', params={})
        ts1 = only_one(only_one(askrene_listlayers_res1['layers'])['constraints'])['timestamp']
        update_example(node=l2, method='askrene-age', params={'layer': 'test_layers', 'cutoff': ts1 + 1})
        update_example(node=l2, method='askrene-remove-layer', params={'layer': 'test_layers'})
        update_example(node=l1, method='getroutes', params={'source': l1.info['id'], 'destination': l3.info['id'], 'amount_msat': 1250000, 'layers': [], 'maxfee_msat': 125000, 'final_cltv': 0})
        update_example(node=l1, method='askrene-reserve', params={'path': [{'short_channel_id_dir': scid12dir, 'amount_msat': 1250_000}, {'short_channel_id_dir': scid23dir, 'amount_msat': 1250_001}]})
        update_example(node=l1, method='askrene-reserve', params={'path': [{'short_channel_id_dir': scid12dir, 'amount_msat': 1250_000_000_000}, {'short_channel_id_dir': scid23dir, 'amount_msat': 1250_000_000_000}]})
        time.sleep(2)
        askrene_listreservations_res1 = l1.rpc.askrene_listreservations()
        update_example(node=l1, method='askrene-listreservations', params={}, response=askrene_listreservations_res1)
        update_example(node=l1, method='askrene-unreserve', params={'path': [{'short_channel_id_dir': scid12dir, 'amount_msat': 1250_000}, {'short_channel_id_dir': scid23dir, 'amount_msat': 1250_001}]})
        update_example(node=l1, method='askrene-unreserve', params={'path': [{'short_channel_id_dir': scid12dir, 'amount_msat': 1250_000_000_000}, {'short_channel_id_dir': scid23dir, 'amount_msat': 1250_000_000_000}]})
        logger.info('Askrene Done!')
    except Exception as e:
        logger.error(f'Error in generating askrene examples: {e}')
        raise


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
        update_example(node=l2, method='waitinvoice', params={'label': 'inv2'}, response=wi2res)

        l1.rpc.pay(inv3['bolt11'])
        wi3res = wi3.result(timeout=5)
        update_example(node=l2, method='waitinvoice', params=['inv3'], response=wi3res)

        # Wait any invoice
        wai = executor.submit(l2.rpc.waitanyinvoice)
        time.sleep(1)
        l1.rpc.pay(inv5['bolt11'])
        l1.rpc.pay(inv4['bolt11'])
        waires = wai.result(timeout=5)
        update_example(node=l2, method='waitanyinvoice', params={}, response=waires)
        pay_index = waires['pay_index']
        wai_pay_index_res = executor.submit(l2.rpc.waitanyinvoice, pay_index, 0).result(timeout=5)
        update_example(node=l2, method='waitanyinvoice', params={'lastpay_index': pay_index, 'timeout': 0}, response=wai_pay_index_res)

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
        update_example(node=l1, method='wait', params={'subsystem': 'sendpays', 'indexname': 'created', 'nextvalue': nextvalue}, response=wspc_res)
        update_example(node=l1, method='wait', params=['sendpays', 'updated', nextvalue], response=wspu_res)

        # Wait blockheight
        curr_blockheight = l2.rpc.getinfo()['blockheight']
        if curr_blockheight < 130:
            bitcoind.generate_block(130 - curr_blockheight)
            sync_blockheight(bitcoind, [l2])
        update_example(node=l2, method='waitblockheight', params={'blockheight': 126}, description=[f'This will return immediately since the current blockheight exceeds the requested waitblockheight.'])
        wbh = executor.submit(l2.rpc.waitblockheight, curr_blockheight + 1, 600)
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l2])
        wbhres = wbh.result(5)
        update_example(node=l2, method='waitblockheight', params={'blockheight': curr_blockheight + 1, 'timeout': 600}, response=wbhres, description=[f'This will return after the next block is mined because requested waitblockheight is one block higher than the current blockheight.'])
        logger.info('Wait Done!')
    except Exception as e:
        logger.error(f'Error in generating wait examples: {e}')
        raise


def generate_utils_examples(l1, l2, l3, l4, l5, l6, c23_2, c34_2, inv_l11, inv_l22, rune_l21, bitcoind):
    """Generates other utilities examples"""
    try:
        logger.info('General Utils Start...')
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
        getlog_res1 = l2.rpc.getlog(level='unusual')
        getlog_res1['log'] = getlog_res1['log'][0:5]
        update_example(node=l2, method='getlog', params={'level': 'unusual'}, response=getlog_res1)
        update_example(node=l2, method='notifications', params={'enable': True})
        update_example(node=l2, method='notifications', params={'enable': False})
        update_example(node=l2, method='check', params={'command_to_check': 'sendpay', 'route': [{'amount_msat': 1011, 'id': l3.info['id'], 'delay': 20, 'channel': c23_2}, {'amount_msat': 1000, 'id': l4.info['id'], 'delay': 10, 'channel': c34_2}], 'payment_hash': '0000000000000000000000000000000000000000000000000000000000000000'})
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
        utxos = [f"{funds_l2['outputs'][2]['txid']}:{funds_l2['outputs'][2]['output']}"]
        withdraw_l22 = update_example(node=l2, method='withdraw', params={'destination': address_l22['p2tr'], 'satoshi': 'all', 'feerate': '20000perkb', 'minconf': 0, 'utxos': utxos})
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
        addr = l2.rpc.newaddr('bech32')['bech32']
        update_example(node=l2, method='signmessagewithkey', params={'message': 'a test message', 'address': addr})
        update_example(node=l2, method='decodepay', params={'bolt11': inv_l11['bolt11']})
        update_example(node=l2, method='decode', params=[rune_l21['rune']])
        update_example(node=l2, method='decode', params=[inv_l22['bolt11']])

        # PSBT
        amount1 = 1000000
        amount2 = 3333333
        psbtoutput_res1 = update_example(node=l1, method='addpsbtoutput', params={'satoshi': amount1, 'locktime': 111}, description=[f'Here is a command to make a PSBT with a {amount1:,} sat output that leads to the on-chain wallet:'])
        update_example(node=l1, method='setpsbtversion', params={'psbt': psbtoutput_res1['psbt'], 'version': 0})
        psbtoutput_res2 = l1.rpc.addpsbtoutput(amount2, psbtoutput_res1['psbt'])
        update_example(node=l1, method='addpsbtoutput', params=[amount2, psbtoutput_res2['psbt']], response=psbtoutput_res2)
        dest = l1.rpc.newaddr('p2tr')['p2tr']
        update_example(node=l1, method='addpsbtoutput', params={'satoshi': amount2, 'initialpsbt': psbtoutput_res2['psbt'], 'destination': dest})
        l1.rpc.addpsbtoutput(amount2, psbtoutput_res2['psbt'], None, dest)
        update_example(node=l1, method='setpsbtversion', params=[psbtoutput_res2['psbt'], 2])

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
        update_example(node=l1, method='sql', params={'query': 'SELECT id FROM peers'}, description=['A simple peers selection query:'])
        update_example(node=l1, method='sql', params=[f"SELECT label, description, status FROM invoices WHERE label='label inv_l12'"], description=["A statement containing `=` needs `-o` in shell:"])
        sql_res3 = l1.rpc.sql(f"SELECT nodeid FROM nodes WHERE nodeid != x'{l3.info['id']}'")
        update_example(node=l1, method='sql', params=[f"SELECT nodeid FROM nodes WHERE nodeid != x'{l3.info['id']}'"], description=['If you want to get specific nodeid values from the nodes table:'], response=sql_res3)
        sql_res4 = l1.rpc.sql(f"SELECT nodeid FROM nodes WHERE nodeid IN (x'{l1.info['id']}', x'{l3.info['id']}')")
        update_example(node=l1, method='sql', params=[f"SELECT nodeid FROM nodes WHERE nodeid IN (x'{l1.info['id']}', x'{l3.info['id']}')"], description=["If you want to compare a BLOB column, `x'hex'` or `X'hex'` are needed:"], response=sql_res4)
        update_example(node=l1, method='sql', params=['SELECT peer_id, to_us_msat, total_msat, peerchannels_status.status FROM peerchannels INNER JOIN peerchannels_status ON peerchannels_status.row = peerchannels.rowid'], description=['Related tables are usually referenced by JOIN:'])
        update_example(node=l2, method='sql', params=['SELECT COUNT(*) FROM forwards'], description=["Simple function usage, in this case COUNT. Strings inside arrays need \", and ' to protect them from the shell:"])
        update_example(node=l1, method='sql', params=['SELECT * from peerchannels_features'])
        getlog_res1['log']
        logger.info('General Utils Done!')
        return address_l22
    except Exception as e:
        logger.error(f'Error in generating utils examples: {e}')
        raise


def generate_splice_examples(node_factory, bitcoind, regenerate_blockchain):
    """Generates splice related examples"""
    try:
        logger.info('Splice Start...')
        # Basic setup for l7->l8
        options = [
            {
                'experimental-splicing': None,
                'allow-deprecated-apis': True,
                'allow_bad_gossip': True,
                'broken_log': '.*',
                'dev-bitcoind-poll': 3,
                'no_entropy': True,
                'base_port': BASE_PORTNUM,
            }.copy()
            for i in range(2)
        ]
        l7, l8 = node_factory.get_nodes(2, opts=options)
        l7.fundwallet(FUND_WALLET_AMOUNT_SAT)
        l7.rpc.connect(l8.info['id'], 'localhost', l8.port)
        c78, c78res = l7.fundchannel(l8, FUND_CHANNEL_AMOUNT_SAT)
        mine_funding_to_announce(bitcoind, [l7, l8])
        l7.wait_channel_active(c78)
        chan_id_78 = l7.get_channel_id(l8)
        # Splice
        funds_result_1 = l7.rpc.fundpsbt('109000sat', 'slow', 166, excess_as_change=True)
        spinit_res1 = update_example(node=l7, method='splice_init', params={'channel_id': chan_id_78, 'relative_amount': 100000, 'initialpsbt': funds_result_1['psbt']})
        spupdate1_res1 = l7.rpc.splice_update(chan_id_78, spinit_res1['psbt'])
        assert(spupdate1_res1['commitments_secured'] is False)
        spupdate2_res1 = update_example(node=l7, method='splice_update', params={'channel_id': chan_id_78, 'psbt': spupdate1_res1['psbt']})
        assert(spupdate2_res1['commitments_secured'] is True)
        signpsbt_res1 = l7.rpc.signpsbt(spupdate2_res1['psbt'])
        update_example(node=l7, method='splice_signed', params={'channel_id': chan_id_78, 'psbt': signpsbt_res1['signed_psbt']})

        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l7])
        l7.daemon.wait_for_log(' to CHANNELD_NORMAL')
        time.sleep(1)

        # Splice out
        funds_result_2 = l7.rpc.addpsbtoutput(100000)

        # Pay with fee by subtracting 5000 from channel balance
        spinit_res2 = update_example(node=l7, method='splice_init', params=[chan_id_78, -105000, funds_result_2['psbt']])
        spupdate1_res2 = l7.rpc.splice_update(chan_id_78, spinit_res2['psbt'])
        assert(spupdate1_res2['commitments_secured'] is False)
        spupdate2_res2 = update_example(node=l7, method='splice_update', params=[chan_id_78, spupdate1_res2['psbt']])
        assert(spupdate2_res2['commitments_secured'] is True)
        update_example(node=l7, method='splice_signed', params={'channel_id': chan_id_78, 'psbt': spupdate2_res2['psbt']})
        update_example(node=l7, method='stop', params={})

        logger.info('Splice Done!')
    except Exception as e:
        logger.error(f'Error in generating splicing examples: {e}')
        raise


def generate_channels_examples(node_factory, bitcoind, l1, l3, l4, l5, regenerate_blockchain):
    """Generates fundchannel and openchannel related examples"""
    try:
        logger.info('Channels Start...')
        # Basic setup for l9->l10 for fundchannel examples
        options = [
            {
                'may_reconnect': True,
                'dev-no-reconnect': None,
                'allow-deprecated-apis': True,
                'allow_bad_gossip': True,
                'broken_log': '.*',
                'dev-bitcoind-poll': 3,
                'no_entropy': True,
                'base_port': BASE_PORTNUM,
            }.copy()
            for i in range(2)
        ]
        l9, l10 = node_factory.get_nodes(2, opts=options)

        amount = 2 ** 24
        l9.fundwallet(amount + 10000000)
        bitcoind.generate_block(1)
        wait_for(lambda: len(l9.rpc.listfunds()["outputs"]) != 0)
        l9.rpc.connect(l10.info['id'], 'localhost', l10.port)

        fund_start_res1 = update_example(node=l9, method='fundchannel_start', params=[l10.info['id'], amount])
        outputs_1 = [{fund_start_res1['funding_address']: amount}]
        [{'bcrt1p00' + ('02' * 28): amount}]
        tx_prep_1 = update_example(node=l9, method='txprepare', params=[outputs_1])
        update_example(node=l9, method='fundchannel_cancel', params=[l10.info['id']])
        update_example(node=l9, method='txdiscard', params=[tx_prep_1['txid']])
        fund_start_res2 = update_example(node=l9, method='fundchannel_start', params={'id': l10.info['id'], 'amount': amount})
        outputs_2 = [{fund_start_res2['funding_address']: amount}]
        [{'bcrt1p00' + ('03' * 28): amount}]
        tx_prep_2 = update_example(node=l9, method='txprepare', params={'outputs': outputs_2})
        update_example(node=l9, method='fundchannel_complete', params=[l10.info['id'], tx_prep_2['psbt']])
        update_example(node=l9, method='txsend', params=[tx_prep_2['txid']])
        l9.rpc.close(l10.info['id'])

        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l9])

        amount = 1000000
        fund_start_res3 = l9.rpc.fundchannel_start(l10.info['id'], amount)
        tx_prep_3 = l9.rpc.txprepare([{fund_start_res3['funding_address']: amount}])
        update_example(node=l9, method='fundchannel_cancel', params={'id': l10.info['id']})
        update_example(node=l9, method='txdiscard', params={'txid': tx_prep_3['txid']})
        funding_addr = l9.rpc.fundchannel_start(l10.info['id'], amount)['funding_address']
        tx_prep_4 = l9.rpc.txprepare([{funding_addr: amount}])
        update_example(node=l9, method='fundchannel_complete', params={'id': l10.info['id'], 'psbt': tx_prep_4['psbt']})
        update_example(node=l9, method='txsend', params={'txid': tx_prep_4['txid']})
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
                'no_entropy': True,
                'base_port': BASE_PORTNUM,
            }.copy()
            for i in range(2)
        ]
        l11, l12 = node_factory.get_nodes(2, opts=options)

        l11.fundwallet(FUND_WALLET_AMOUNT_SAT)
        l11.rpc.connect(l12.info['id'], 'localhost', l12.port)
        c1112res = l11.rpc.fundchannel(l12.info['id'], FUND_CHANNEL_AMOUNT_SAT)
        chan_id = c1112res['channel_id']
        vins = bitcoind.rpc.decoderawtransaction(c1112res['tx'])['vin']
        assert(only_one(vins))
        prev_utxos = ["{}:{}".format(vins[0]['txid'], vins[0]['vout'])]

        l1.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')
        chan = only_one(l11.rpc.listpeerchannels(l12.info['id'])['channels'])
        rate = int(chan['feerate']['perkw'])
        next_feerate = '{}perkw'.format(rate * 4)

        # Initiate an RBF
        startweight = 42 + 172
        initpsbt_1 = update_example(node=l11, method='utxopsbt', params=[FUND_CHANNEL_AMOUNT_SAT, next_feerate, startweight, prev_utxos, None, True, None, None, True])
        update_example(node=l11, method='openchannel_bump', params=[chan_id, FUND_CHANNEL_AMOUNT_SAT, initpsbt_1['psbt'], next_feerate])

        update_example(node=l11, method='openchannel_abort', params={'channel_id': chan_id})
        openchannelbump_res2 = update_example(node=l11, method='openchannel_bump', params={'channel_id': chan_id, 'amount': FUND_CHANNEL_AMOUNT_SAT, 'initialpsbt': initpsbt_1['psbt'], 'funding_feerate': next_feerate})
        openchannelupdate_res1 = update_example(node=l11, method='openchannel_update', params={'channel_id': chan_id, 'psbt': openchannelbump_res2['psbt']})
        signed_psbt_1 = update_example(node=l11, method='signpsbt', params={'psbt': openchannelupdate_res1['psbt']})
        update_example(node=l11, method='openchannel_signed', params={'channel_id': chan_id, 'signed_psbt': signed_psbt_1['signed_psbt']})

        # 5x the feerate to beat the min-relay fee
        chan = only_one(l11.rpc.listpeerchannels(l12.info['id'])['channels'])
        rate = int(chan['feerate']['perkw'])
        next_feerate = '{}perkw'.format(rate * 5)

        # Another RBF with double the channel amount
        startweight = 42 + 172
        initpsbt_2 = update_example(node=l11, method='utxopsbt', params={'satoshi': FUND_CHANNEL_AMOUNT_SAT * 2, 'feerate': next_feerate, 'startweight': startweight, 'utxos': prev_utxos, 'reservedok': True, 'excess_as_change': True})
        openchannelbump_res3 = update_example(node=l11, method='openchannel_bump', params=[chan_id, FUND_CHANNEL_AMOUNT_SAT * 2, initpsbt_2['psbt'], next_feerate])
        openchannelupdate_res2 = update_example(node=l11, method='openchannel_update', params=[chan_id, openchannelbump_res3['psbt']])
        signed_psbt_2 = update_example(node=l11, method='signpsbt', params=[openchannelupdate_res2['psbt']])
        update_example(node=l11, method='openchannel_signed', params=[chan_id, signed_psbt_2['signed_psbt']])

        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l11])
        l11.daemon.wait_for_log(' to CHANNELD_NORMAL')

        # Fundpsbt, channelopen init, abort, unreserve
        psbt_init_res1 = update_example(node=l11, method='fundpsbt', params={'satoshi': FUND_CHANNEL_AMOUNT_SAT, 'feerate': '253perkw', 'startweight': 250, 'reserve': 0})
        openchannelinit_res1 = update_example(node=l11, method='openchannel_init', params={'id': l12.info['id'], 'amount': FUND_CHANNEL_AMOUNT_SAT, 'initialpsbt': psbt_init_res1['psbt']})
        l11.rpc.openchannel_abort(openchannelinit_res1['channel_id'])
        update_example(node=l11, method='unreserveinputs', params={'psbt': psbt_init_res1['psbt'], 'reserve': 200})

        psbt_init_res2 = update_example(node=l11, method='fundpsbt', params={'satoshi': FUND_CHANNEL_AMOUNT_SAT // 2, 'feerate': 'urgent', 'startweight': 166, 'reserve': 0, 'excess_as_change': True, 'min_witness_weight': 110})
        openchannelinit_res2 = update_example(node=l11, method='openchannel_init', params=[l12.info['id'], FUND_CHANNEL_AMOUNT_SAT // 2, psbt_init_res2['psbt']])
        l11.rpc.openchannel_abort(openchannelinit_res2['channel_id'])
        update_example(node=l11, method='unreserveinputs', params=[psbt_init_res2['psbt']])

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
        outputs = sorted(l4.rpc.listfunds()['outputs'], key=lambda o: o["amount_msat"], reverse=True)
        utxo = f"{outputs[0]['txid']}:{outputs[0]['output']}"
        c41res = update_example(node=l4, method='fundchannel',
                                params={'id': l1.info['id'], 'amount': 'all', 'feerate': 'normal', 'push_msat': 100000, 'utxos': [utxo]},
                                description=[f'This example shows how to to open new channel with peer 1 from one whole utxo (you can use **listfunds** command to get txid and vout):'])
        # Close newly funded channels to bring the setup back to initial state
        l3.rpc.close(c35res['channel_id'])
        l4.rpc.close(c41res['channel_id'])
        l3.rpc.disconnect(l5.info['id'], True)
        l4.rpc.disconnect(l1.info['id'], True)

        # Multifundchannel 2
        l1.fundwallet(10**8)
        l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
        l1.rpc.connect(l4.info['id'], 'localhost', l4.port)
        l1.rpc.connect(l5.info['id'], 'localhost', l5.port)
        destinations_1 = [
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
        ]
        multifund_res1 = update_example(node=l1, method='multifundchannel', params={
            'destinations': destinations_1,
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

        destinations_2 = [
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
        ]
        multifund_res2 = update_example(node=l1, method='multifundchannel', params={'destinations': destinations_2, 'minchannels': 1})
        # Close newly funded channels to bring the setup back to initial state
        for channel in multifund_res2['channel_ids']:
            l1.rpc.close(channel['channel_id'])
        l1.rpc.disconnect(l3.info['id'], True)
        l1.rpc.disconnect(l4.info['id'], True)
        l1.rpc.disconnect(l5.info['id'], True)
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l1, l3, l4, l5])
        logger.info('Channels Done!')
    except Exception as e:
        logger.error(f'Error in generating fundchannel and openchannel examples: {e}')
        raise


def generate_autoclean_delete_examples(l1, l2, l3, l4, l5, c12, c23):
    """Records autoclean and delete examples"""
    try:
        logger.info('Auto-clean and Delete Start...')
        l2.rpc.close(l5.info['id'])
        update_example(node=l2, method='dev-forget-channel', params={'id': l5.info['id']}, description=[f'Forget a channel by peer pubkey when only one channel exists with the peer:'])

        # Create invoices for delpay and delinvoice examples
        inv_l35 = l3.rpc.invoice('50000sat', 'lbl_l35', 'l35 description')
        inv_l36 = l3.rpc.invoice('50000sat', 'lbl_l36', 'l36 description')
        inv_l37 = l3.rpc.invoice('50000sat', 'lbl_l37', 'l37 description')

        # For MPP payment from l1 to l4; will use for delpay groupdid and partid example
        inv_l41 = l4.rpc.invoice('5000sat', 'lbl_l41', 'l41 description')
        l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
        c24, c24res = l2.fundchannel(l4, FUND_CHANNEL_AMOUNT_SAT)
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
            update_example(node=l2, method='delforward', params={'in_channel': c12, 'in_htlc_id': failed_forwards[0]['in_htlc_id'], 'status': 'failed'})
        update_example(node=l2, method='dev-forget-channel', params={'id': l3.info['id'], 'short_channel_id': c23, 'force': True}, description=[f'Forget a channel by short channel id when peer has multiple channels:'])

        # Autoclean
        update_example(node=l2, method='autoclean-once', params=['failedpays', 1])
        update_example(node=l2, method='autoclean-once', params=['succeededpays', 1])
        update_example(node=l2, method='autoclean-status', params={'subsystem': 'expiredinvoices'})
        update_example(node=l2, method='autoclean-status', params={})
        logger.info('Auto-clean and Delete Done!')
    except Exception as e:
        logger.error(f'Error in generating autoclean and delete examples: {e}')
        raise


def generate_backup_recovery_examples(node_factory, l4, l5, l6, regenerate_blockchain):
    """Node backup and recovery examples"""
    try:
        logger.info('Backup and Recovery Start...')

        # New node l13 used for recover and exposesecret examples
        l13 = node_factory.get_node(options={'exposesecret-passphrase': "test_exposesecret"}, no_entropy=True, base_portnum=BASE_PORTNUM)
        update_example(node=l13, method='exposesecret', params={'passphrase': 'test_exposesecret'})
        update_example(node=l13, method='exposesecret', params=['test_exposesecret', 'cln2'])

        update_example(node=l5, method='makesecret', params=['73636220736563726574'])
        update_example(node=l5, method='makesecret', params={'string': 'scb secret'})
        emergencyrecover_res1 = l4.rpc.emergencyrecover()
        emergencyrecover_res1['stubs'].sort()
        update_example(node=l4, method='emergencyrecover', params={}, response=emergencyrecover_res1)
        update_example(node=l4, method='getemergencyrecoverdata', params={}, response='emergencyrecoverdata' + ('01' * 827))
        backup_l4 = update_example(node=l4, method='staticbackup', params={})

        # Recover channels
        l4.stop()
        os.unlink(os.path.join(l4.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3'))
        l4.start()
        time.sleep(1)
        recoverchannel_res1 = l4.rpc.recoverchannel(backup_l4['scb'])
        recoverchannel_res1['stubs'].sort()
        update_example(node=l4, method='recoverchannel', params={'scb': backup_l4['scb']}, response=recoverchannel_res1)
        # Emergency recover
        l5.stop()
        os.unlink(os.path.join(l5.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3'))
        l5.start()
        time.sleep(1)
        emergencyrecover_res2 = l5.rpc.emergencyrecover()
        emergencyrecover_res2['stubs'].sort()
        update_example(node=l5, method='emergencyrecover', params={}, response=emergencyrecover_res2)

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
                raise

        _, l6hex = get_hsm_secret(l6)
        l13codex32, _ = get_hsm_secret(l13)
        update_example(node=l6, method='recover', params={'hsmsecret': l6hex})
        update_example(node=l13, method='recover', params={'hsmsecret': l13codex32})
        logger.info('Backup and Recovery Done!')
    except Exception as e:
        logger.error(f'Error in generating backup and recovery examples: {e}')
        raise


def generate_list_examples(bitcoind, l1, l2, l3, c12, c23_2, inv_l31, inv_l32, offer_l23, inv_req_l1_l22, address_l22):
    """Generates lists rpc examples"""
    try:
        logger.info('Lists Start...')
        # Make sure all nodes are caught up.
        sync_blockheight(bitcoind, [l1, l2, l3])
        # Transactions Lists
        listfunds_res1 = l2.rpc.listfunds()
        update_example(node=l2, method='listfunds', params={}, response=listfunds_res1)

        listforwards_res1 = l2.rpc.listforwards(in_channel=c12, out_channel=c23_2, status='settled')
        update_example(node=l2, method='listforwards', params={'in_channel': c12, 'out_channel': c23_2, 'status': 'settled'}, response=listforwards_res1)
        listforwards_res2 = l2.rpc.listforwards()
        update_example(node=l2, method='listforwards', params={}, response=listforwards_res2)

        listinvoices_res1 = l2.rpc.listinvoices(label='lbl_l21')
        update_example(node=l2, method='listinvoices', params={'label': 'lbl_l21'}, response=listinvoices_res1)
        listinvoices_res2 = l2.rpc.listinvoices()
        update_example(node=l2, method='listinvoices', params={}, response=listinvoices_res2)

        listhtlcs_res1 = l1.rpc.listhtlcs(c12)
        update_example(node=l1, method='listhtlcs', params=[c12], response=listhtlcs_res1)
        listhtlcs_res2 = l1.rpc.listhtlcs(index='created', start=4, limit=1)
        update_example(node=l1, method='listhtlcs', params={'index': 'created', 'start': 4, 'limit': 1}, response=listhtlcs_res2)

        listsendpays_res1 = l1.rpc.listsendpays(bolt11=inv_l31['bolt11'])
        update_example(node=l1, method='listsendpays', params={'bolt11': inv_l31['bolt11']}, response=listsendpays_res1)
        listsendpays_res2 = l1.rpc.listsendpays()
        update_example(node=l1, method='listsendpays', params={}, response=listsendpays_res2)

        listpays_res1 = l2.rpc.listpays(bolt11=inv_l32['bolt11'])
        update_example(node=l2, method='listpays', params={'bolt11': inv_l32['bolt11']}, response=listpays_res1)
        listpays_res2 = l2.rpc.listpays()
        update_example(node=l2, method='listpays', params={}, response=listpays_res2)

        listtransactions_res3 = l3.rpc.listtransactions()
        update_example(node=l3, method='listtransactions', params={}, response=listtransactions_res3)
        listclosedchannels_res1 = l2.rpc.listclosedchannels()
        update_example(node=l2, method='listclosedchannels', params={}, response=listclosedchannels_res1)

        update_example(node=l2, method='listconfigs', params={'config': 'network'})
        update_example(node=l2, method='listconfigs', params={'config': 'experimental-dual-fund'})
        l2.rpc.jsonschemas = {}
        listconfigs_res3 = l2.rpc.listconfigs()
        update_example(node=l2, method='listconfigs', params={}, response=listconfigs_res3)

        update_example(node=l2, method='listsqlschemas', params={'table': 'offers'})
        update_example(node=l2, method='listsqlschemas', params=['closedchannels'])

        listpeerchannels_res1 = l2.rpc.listpeerchannels(l1.info['id'])
        update_example(node=l2, method='listpeerchannels', params={'id': l1.info['id']}, response=listpeerchannels_res1)
        listpeerchannels_res2 = l2.rpc.listpeerchannels()
        update_example(node=l2, method='listpeerchannels', params={}, response=listpeerchannels_res2)

        listchannels_res1 = l1.rpc.listchannels(c12)
        update_example(node=l1, method='listchannels', params={'short_channel_id': c12}, response=listchannels_res1)
        listchannels_res2 = l2.rpc.listchannels()
        update_example(node=l2, method='listchannels', params={}, response=listchannels_res2)

        listnodes_res1 = l2.rpc.listnodes(l3.info['id'])
        update_example(node=l2, method='listnodes', params={'id': l3.info['id']}, response=listnodes_res1)
        listnodes_res2 = l2.rpc.listnodes()
        update_example(node=l2, method='listnodes', params={}, response=listnodes_res2)

        listpeers_res1 = l2.rpc.listpeers(l3.info['id'])
        update_example(node=l2, method='listpeers', params={'id': l3.info['id']}, response=listpeers_res1)
        listpeers_res2 = l2.rpc.listpeers()
        update_example(node=l2, method='listpeers', params={}, response=listpeers_res2)

        update_example(node=l2, method='listdatastore', params={'key': ['employee']})
        update_example(node=l2, method='listdatastore', params={'key': 'somekey'})

        listoffers_res1 = l2.rpc.listoffers(active_only=True)
        update_example(node=l2, method='listoffers', params={'active_only': True}, response=listoffers_res1)
        listoffers_res2 = l2.rpc.listoffers(offer_id=offer_l23['offer_id'])
        update_example(node=l2, method='listoffers', params=[offer_l23['offer_id']], response=listoffers_res2)

        update_example(node=l2, method='listinvoicerequests', params=[inv_req_l1_l22['invreq_id']])
        listinvoicerequests_res2 = l2.rpc.listinvoicerequests()
        update_example(node=l2, method='listinvoicerequests', params={}, response=listinvoicerequests_res2)
        update_example(node=l2, method='listaddresses', params=[address_l22['p2tr']])
        update_example(node=l2, method='listaddresses', params={'start': 6, 'limit': 2})
        logger.info('Lists Done!')
    except Exception as e:
        logger.error(f'Error in generating lists examples: {e}')
        raise


@pytest.fixture(autouse=True)
def setup_logging():
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


@unittest.skipIf(not GENERATE_EXAMPLES, 'Generates examples for doc/schema/lightning-*.json files.')
@pytest.mark.parametrize('bitcoind', [False], indirect=True)
def test_generate_examples(node_factory, bitcoind, executor):
    """Re-generates examples for doc/schema/lightning-*.json files"""

    # Change this to True to regenerate bitcoin block & wallet.
    regenerate_blockchain = (os.environ.get("REGENERATE_BLOCKCHAIN") == "1")
    wallet_exists = os.access("tests/data/autogenerate-bitcoind-wallet.dat", os.F_OK)

    # Make sure we can get the ports we expect.
    check_ports(range(BASE_PORTNUM + 1, BASE_PORTNUM + 40))

    # Make sure bitcoind doesn't steal our ports!
    bitcoind.set_port(BASE_PORTNUM)

    try:
        global ALL_RPC_EXAMPLES, REGENERATING_RPCS

        if regenerate_blockchain:
            if wallet_exists:
                bitcoind.start(wallet_file="tests/data/autogenerate-bitcoind-wallet.dat")
            else:
                bitcoind.start()
        else:
            # This was created by bitcoind.rpc.backupwallet.  Probably unnecessary,
            # but reduces gratuitous differences if we have to regenerate the blockchain.
            bitcoind.start(wallet_file="tests/data/autogenerate-bitcoind-wallet.dat")
            with open("tests/data/autogenerate-bitcoin-blocks.json", "r") as f:
                canned_blocks = json.load(f)
            bitcoind.set_canned_blocks(canned_blocks)

        info = bitcoind.rpc.getblockchaininfo()
        assert info['blocks'] == 0
        print(bitcoind.rpc.listwallets())
        # 102 is a funny story.  When we *submitblock* the first 101 blocks,
        # our wallet balance is 0.  When we *generate* the frist 101 blocks,
        # our wallet balance is 50.
        if info['blocks'] < 102:
            bitcoind.generate_block(102 - info['blocks'])
        assert bitcoind.rpc.getbalance() > 0

        def list_all_examples():
            """list all methods used in 'update_example' calls to ensure that all methods are covered"""
            try:
                methods = []
                file_path = os.path.abspath(__file__)

                # Parse and traverse this file's content to list all methods & file names
                with open(file_path, "r") as file:
                    file_content = file.read()
                tree = ast.parse(file_content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'update_example':
                        for keyword in node.keywords:
                            if (keyword.arg == 'method' and isinstance(keyword.value, ast.Constant)):
                                if keyword.value.value not in methods:
                                    methods.append(keyword.value.value)
                return methods
            except Exception as e:
                logger.error(f'Error in listing all examples: {e}')
                raise

        def list_missing_examples():
            """Checks for missing example & log an error if missing."""
            try:
                missing_examples = ''
                for file_name in os.listdir('doc/schemas'):
                    if not file_name.endswith('.json'):
                        continue
                    file_name_str = str(file_name).replace('.json', '')
                    # Log an error if the method is not in the list
                    if file_name_str not in ALL_RPC_EXAMPLES and file_name_str not in IGNORE_RPCS_LIST:
                        missing_examples = missing_examples + f"'{file_name_str}', "
                if missing_examples != '':
                    raise MissingExampleError(f"Missing {missing_examples.count(', ')} Examples For: [{missing_examples.rstrip(', ')}]")
            except MissingExampleError:
                raise
            except Exception as e:
                logger.error(f'Error in listing missing examples: {e}')
                raise

        ALL_RPC_EXAMPLES = list_all_examples()
        logger.info(f'This test can reproduce examples for {len(ALL_RPC_EXAMPLES)} methods: {ALL_RPC_EXAMPLES}')
        logger.warning(f'This test ignores {len(IGNORE_RPCS_LIST)} rpc methods: {IGNORE_RPCS_LIST}')
        REGENERATING_RPCS = [rpc.strip() for rpc in os.getenv("REGENERATE").split(', ')] if os.getenv("REGENERATE") else ALL_RPC_EXAMPLES
        list_missing_examples()

        # We make sure everyone is on predicable time
        os.environ['CLN_DEV_SET_TIME'] = '1738000000'

        l1, l2, l3, l4, l5, l6, c12, c23, c25 = setup_test_nodes(node_factory, bitcoind, regenerate_blockchain)
        c23_2, c23res2, c34_2, inv_l11, inv_l21, inv_l22, inv_l31, inv_l32, inv_l34 = generate_transactions_examples(l1, l2, l3, l4, l5, c25, bitcoind)
        rune_l21 = generate_runes_examples(l1, l2, l3)
        generate_datastore_examples(l2)
        generate_coinmvt_examples(l2)
        generate_bookkeeper_examples(l2, l3, c23res2['channel_id'])
        offer_l23, inv_req_l1_l22 = generate_offers_renepay_examples(l1, l2, inv_l21, inv_l34)
        generate_askrene_examples(l1, l2, l3, c12, c23_2)
        generate_wait_examples(l1, l2, bitcoind, executor)
        address_l22 = generate_utils_examples(l1, l2, l3, l4, l5, l6, c23_2, c34_2, inv_l11, inv_l22, rune_l21, bitcoind)
        generate_splice_examples(node_factory, bitcoind, regenerate_blockchain)
        generate_channels_examples(node_factory, bitcoind, l1, l3, l4, l5, regenerate_blockchain)
        generate_autoclean_delete_examples(l1, l2, l3, l4, l5, c12, c23)
        generate_backup_recovery_examples(node_factory, l4, l5, l6, regenerate_blockchain)
        generate_list_examples(bitcoind, l1, l2, l3, c12, c23_2, inv_l31, inv_l32, offer_l23, inv_req_l1_l22, address_l22)
        update_examples_in_schema_files()
        logger.info('All Done!!!')
    except Exception as e:
        logger.error(e, exc_info=True)
        sys.exit(1)

    if regenerate_blockchain:
        with open("tests/data/autogenerate-bitcoin-blocks.json", "w") as blockfile:
            print(json.dump(bitcoind.save_blocks(), blockfile))
        logger.info('tests/data/autogenerate-bitcoin-blocks.json updated')

        # Very first run, we can dump wallet too.
        if not wallet_exists:
            bitcoind.rpc.backupwallet("tests/data/autogenerate-bitcoind-wallet.dat")
            logger.info('tests/data/autogenerate-bitcoind-wallet.dat regenerated')
