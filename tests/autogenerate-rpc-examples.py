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
import sys
import os
import re
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
TEMP_EXAMPLES_FILE = './tests/autogenerate-examples.json'
IGNORE_RPCS_LIST = ['dev-splice', 'reckless', 'sql-template']

# Constants for replacing values in examples
NEW_VALUES_LIST = {
    'root_dir': '/root/lightning',
    'tmp_dir': '/tmp/.lightning',
    'str_1': '1',
    'num_1': 1,
    'balance_msat_1': 202050000000,
    'fees_paid_msat_1': 5020000,
    'bytes_used': 1630000,
    'bytes_max': 10485760,
    'assocdata_1': 'assocdata0' + ('01' * 27),
    'hsm_secret_cdx_1': 'cl10leetsd35kw6r5de5kueedxyesqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqluplcg0lxenqd',
    'error_message_1': 'All addresses failed: 127.0.0.1:19736: Cryptographic handshake: peer closed connection (wrong key?). ',
    'configs_3_addr2': "127.0.0.1:19735",
    'bitcoin-rpcport': 18332,
    'grpc-port': 9736,
    'blockheight_110': 110,
    'blockheight_130': 130,
    'blockheight_160': 160,
    'script_pubkey_1': 'scriptpubkey' + ('01' * 28),
    'script_pubkey_2': 'scriptpubkey' + ('02' * 28),
    'onion_1': 'onion' + ('10' * 1363),
    'onion_2': 'onion' + ('20' * 1363),
    'onion_3': 'onion' + ('30' * 1363),
    'shared_secrets_1': ['sharedsecret' + ('10' * 26), 'sharedsecret' + ('11' * 26), 'sharedsecret' + ('12' * 26)],
    'shared_secrets_2': ['sharedsecret' + ('20' * 26), 'sharedsecret' + ('21' * 26), 'sharedsecret' + ('22' * 26)],
    'invreq_id_1': 'invreqid' + ('01' * 28),
    'invreq_id_2': 'invreqid' + ('02' * 28),
    'invreq_id_l1_l22': 'invreqid' + ('03' * 28),
    'invoice_1': 'lni1qqg0qe' + ('01' * 415),
    'invoice_2': 'lni1qqg0qe' + ('02' * 415),
    'invoice_3': 'lni1qqg0qe' + ('03' * 415),
    'funding_txid_1': 'fundingtxid001' + ('01' * 25),
    'funding_txid_2': 'fundingtxid002' + ('02' * 25),
    'signature_1': 'dcde30c4bb50bed221009d' + ('01' * 60),
    'signature_2': 'dcdepay30c4bb50bed209d' + ('02' * 60),
    'destination_1': 'bcrt1p52' + ('01' * 28),
    'destination_2': 'bcrt1qcqqv' + ('01' * 17),
    'destination_3': 'bcrt1phtprcvhz' + ('02' * 25),
    'destination_4': 'bcrt1p00' + ('02' * 28),
    'destination_5': 'bcrt1p00' + ('03' * 28),
    'destination_6': 'bcrt1p00' + ('04' * 28),
    'destination_7': 'bcrt1p338x' + ('07' * 28),
    'funding_serial_1': 17725655605188010000,
    'funding_serial_2': 17725655605188020000,
    'funding_serial_3': 17725655605188030000,
    'funding_serial_4': 17725655605188040000,
    'funding_serial_5': 17725655605188050000,
    'l1_id': 'nodeid' + ('01' * 30),
    'l2_id': 'nodeid' + ('02' * 30),
    'l3_id': 'nodeid' + ('03' * 30),
    'l4_id': 'nodeid' + ('04' * 30),
    'l5_id': 'nodeid' + ('05' * 30),
    'l10_id': 'nodeid' + ('10' * 30),
    'l12_id': 'nodeid' + ('12' * 30),
    'l1_alias': 'JUNIORBEAM',
    'l2_alias': 'SILENTARTIST',
    'l3_alias': 'HOPPINGFIRE',
    'l4_alias': 'JUNIORFELONY',
    'l2_port': 19735,
    'l3_port': 19736,
    'l1_addr': '127.0.0.1:19734',
    'l2_addr': '127.0.0.1:19735',
    'l3_addr': '127.0.0.1:19736',
    'l4_addr': '127.0.0.1:19737',
    'l5_addr': '127.0.0.1:19738',
    'l6_addr': '127.0.0.1:19739',
    'c12': '109x1x1',
    'c23': '111x1x1',
    'c23_2': '123x1x1',
    'c25': '115x1x1',
    'c34': '125x1x1',
    'c34_2': '130x1x1',
    'c35_tx': '020000000000305fundchanneltx' + ('35000' * 99),
    'c41_tx': '020000000000401fundchanneltx' + ('41000' * 99),
    'upgrade_tx': '02000000000101upgd' + ('20000' * 34),
    'close1_tx': '02000000000101cls0' + ('01' * 200),
    'close2_tx': '02000000000101cls1' + ('02' * 200),
    'send_tx_1': '02000000000101sendpt' + ('64000' * 100),
    'send_tx_2': '02000000000102sendpt' + ('65000' * 100),
    'tx_55': '02000000000155multiw' + ('55000' * 100),
    'tx_56': '02000000000155multiw' + ('56000' * 100),
    'tx_61': '02000000000155multiw' + ('61000' * 100),
    'tx_91': '020000000001wthdrw' + ('91000' * 100),
    'tx_92': '020000000002wthdrw' + ('92000' * 100),
    'unsigned_tx_1': '0200000000' + ('0002' * 66),
    'unsigned_tx_3': '0200000000' + ('0006' * 66),
    'unsigned_tx_4': '0200000000' + ('0008' * 66),
    'multi_tx_1': '02000000000101multif' + ('50000' * 100),
    'multi_tx_2': '02000000000102multif' + ('60000' * 100),
    'ocs_tx_1': '02000000000101sgpsbt' + ('11000' * 100),
    'ocs_tx_2': '02000000000101sgpsbt' + ('12000' * 100),
    'txsend_tx_1': '02000000000101txsend' + ('00011' * 100),
    'txsend_tx_2': '02000000000101txsend' + ('00022' * 100),
    'c12_txid': 'channeltxid' + ('120000' * 9),
    'c23_txid': 'channeltxid' + ('230000' * 9),
    'c23_2_txid': 'channeltxid' + ('230200' * 9),
    'c34_txid': 'channeltxid' + ('340000' * 9),
    'c34_2_txid': 'channeltxid' + ('340200' * 9),
    'c35_txid': 'channeltxid' + ('350000' * 9),
    'c41_txid': 'channeltxid' + ('410000' * 9),
    'c1112_txid': 'channeltxid' + ('111200' * 9),
    'upgrade_txid': 'txidupgrade' + ('200000' * 9),
    'close1_txid': 'txid' + ('01' * 30),
    'close2_txid': 'txid' + ('02' * 30),
    'send_txid_1': 'txid' + ('64000' * 11),
    'send_txid_2': 'txid' + ('65000' * 11),
    'txid_55': 'txid' + ('55000' * 11),
    'txid_56': 'txid' + ('56000' * 11),
    'txid_61': 'txid' + ('61000' * 11),
    'withdraw_txid_l21': 'txidwithdraw21' + ('91000' * 10),
    'withdraw_txid_l22': 'txidwithdraw22' + ('92000' * 10),
    'txprep_txid_1': 'txidtxprep0001' + ('00001' * 10),
    'txprep_txid_2': 'txidtxprep0002' + ('00002' * 10),
    'txprep_txid_3': 'txidtxprep0003' + ('00003' * 10),
    'txprep_txid_4': 'txidtxprep0004' + ('00004' * 10),
    'multi_txid_1': 'channeltxid010' + ('50000' * 10),
    'multi_txid_2': 'channeltxid020' + ('60000' * 10),
    'utxo_1': 'utxo' + ('01' * 30),
    'ocs_txid_1': 'txidocsigned10' + ('11000' * 10),
    'ocs_txid_2': 'txidocsigned10' + ('12000' * 10),
    'c12_channel_id': 'channelid0' + ('120000' * 9),
    'c23_channel_id': 'channelid0' + ('230000' * 9),
    'c23_2_channel_id': 'channelid0' + ('230200' * 9),
    'c25_channel_id': 'channelid0' + ('250000' * 9),
    'c34_channel_id': 'channelid0' + ('340000' * 9),
    'c34_2_channel_id': 'channelid0' + ('340200' * 9),
    'c35_channel_id': 'channelid0' + ('350000' * 9),
    'c41_channel_id': 'channelid0' + ('410000' * 9),
    'c78_channel_id': 'channelid0' + ('780000' * 9),
    'c1112_channel_id': 'channelid0' + ('111200' * 9),
    'c910_channel_id_1': 'channelid' + ('09101' * 11),
    'c910_channel_id_2': 'channelid' + ('09102' * 11),
    'mf_channel_id_1': 'channelid' + ('11000' * 11),
    'mf_channel_id_2': 'channelid' + ('12000' * 11),
    'mf_channel_id_3': 'channelid' + ('13000' * 11),
    'mf_channel_id_4': 'channelid' + ('15200' * 11),
    'mf_channel_id_5': 'channelid' + ('12400' * 11),
    'time_at_800': 1738000000,
    'time_at_850': 1738500000,
    'time_at_900': 1739000000,
    'bolt11_l11': 'lnbcrt100n1pnt2' + ('bolt11invl010100000000' * 10),
    'bolt11_l12': 'lnbcrt100n1pnt2' + ('bolt11invl010200000000' * 10),
    'bolt11_l13': 'lnbcrt100n1pnt2' + ('bolt11invl010300000000' * 10),
    'bolt11_l14': 'lnbcrt100n1pnt2' + ('bolt11invl010400000000' * 10),
    'bolt11_l21': 'lnbcrt100n1pnt2' + ('bolt11invl020100000000' * 10),
    'bolt11_l22': 'lnbcrt100n1pnt2' + ('bolt11invl020200000000' * 10),
    'bolt11_l23': 'lnbcrt100n1pnt2' + ('bolt11invl020300000000' * 10),
    'bolt11_l24': 'lnbcrt100n1pnt2' + ('bolt11invl020400000000' * 10),
    'bolt11_l25': 'lnbcrt100n1pnt2' + ('bolt11invl020500000000' * 10),
    'bolt11_l26': 'lnbcrt100n1pnt2' + ('bolt11invl020600000000' * 10),
    'bolt11_l27': 'lnbcrt100n1pnt2' + ('bolt11invl020700000000' * 10),
    'bolt11_l31': 'lnbcrt100n1pnt2' + ('bolt11invl030100000000' * 10),
    'bolt11_l33': 'lnbcrt100n1pnt2' + ('bolt11invl030300000000' * 10),
    'bolt11_l34': 'lnbcrt100n1pnt2' + ('bolt11invl030400000000' * 10),
    'bolt11_l41': 'lnbcrt100n1pnt2' + ('bolt11invl040100000000' * 10),
    'bolt11_l66': 'lnbcrt100n1pnt2' + ('bolt11invl060600000000' * 10),
    'bolt11_l67': 'lnbcrt100n1pnt2' + ('bolt11invl060700000000' * 10),
    'bolt11_wt_1': 'lnbcrt222n1pnt3005720bolt11wtinv' + ('01' * 160),
    'bolt11_wt_2': 'lnbcrt222n1pnt3005720bolt11wtinv' + ('02' * 160),
    'bolt11_di_1': 'lnbcrt222n1pnt3005720bolt11300' + ('01' * 170),
    'bolt11_di_2': 'lnbcrt222n1pnt3005720bolt11300' + ('01' * 170),
    'bolt11_dp_1': 'lnbcrt222n1pnt3005720bolt11400' + ('01' * 170),
    'bolt12_l21': 'lno1qgsq000bolt' + ('21000' * 24),
    'bolt12_l22': 'lno1qgsq000bolt' + ('22000' * 24),
    'bolt12_l23': 'lno1qgsq000bolt' + ('23000' * 24),
    'bolt12_l24': 'lno1qgsq000bolt' + ('24000' * 24),
    'bolt12_si_1': 'lno1qgsq000bolt' + ('si100' * 24),
    'offerid_l21': 'offeridl' + ('2100000' * 8),
    'offerid_l22': 'offeridl' + ('2200000' * 8),
    'offerid_l23': 'offeridl' + ('2300000' * 8),
    'payment_hash_l11': 'paymenthashinvl0' + ('1100' * 12),
    'payment_hash_l21': 'paymenthashinvl0' + ('2100' * 12),
    'payment_hash_l22': 'paymenthashinvl0' + ('2200' * 12),
    'payment_hash_l27': 'paymenthashinvl0' + ('2700' * 12),
    'payment_hash_l31': 'paymenthashinvl0' + ('3100' * 12),
    'payment_hash_l24': 'paymenthashinvl0' + ('2400' * 12),
    'payment_hash_l25': 'paymenthashinvl0' + ('2500' * 12),
    'payment_hash_l26': 'paymenthashinvl0' + ('2600' * 12),
    'payment_hash_l33': 'paymenthashinvl0' + ('3300' * 12),
    'payment_hash_l34': 'paymenthashinvl0' + ('3400' * 12),
    'payment_hash_key_1': 'paymenthashkey01' + ('k101' * 12),
    'payment_hash_key_2': 'paymenthashkey02' + ('k201' * 12),
    'payment_hash_key_3': 'paymenthashkey03' + ('k301' * 12),
    'payment_hash_cmd_pay_1': 'paymenthashcmdpy' + ('cp10' * 12),
    'payment_hash_si_1': 'paymenthashsdinv' + ('si10' * 12),
    'payment_hash_wspc_1': 'paymenthashwtspct2' + ('01' * 23),
    'payment_hash_winv_1': 'paymenthashwaitinv' + ('01' * 23),
    'payment_hash_winv_2': 'paymenthashwaitinv' + ('02' * 23),
    'payment_hash_di_1': 'paymenthashdelinv1' + ('01' * 23),
    'payment_hash_di_2': 'paymenthashdelinv2' + ('02' * 23),
    'payment_hash_dp_1': 'paymenthashdelpay1' + ('01' * 23),
    'payment_hash_dp_2': 'paymenthashdelpay2' + ('02' * 23),
    'payment_hash_dp_3': 'paymenthashdelpay3' + ('03' * 23),
    'payment_preimage_1': 'paymentpreimage1' + ('01' * 24),
    'payment_preimage_2': 'paymentpreimage2' + ('02' * 24),
    'payment_preimage_3': 'paymentpreimage3' + ('03' * 24),
    'payment_preimage_ep_1': 'paymentpreimagep' + ('01' * 24),
    'payment_preimage_ep_2': 'paymentpreimagep' + ('02' * 24),
    'payments_preimage_i_1': 'paymentpreimagei' + ('01' * 24),
    'payments_preimage_w_1': 'paymentpreimagew' + ('01' * 24),
    'payment_preimage_cmd_1': 'paymentpreimagec' + ('01' * 24),
    'payment_preimage_r_1': 'paymentpreimager' + ('01' * 24),
    'payment_preimage_r_2': 'paymentpreimager' + ('02' * 24),
    'payment_preimage_wi_1': 'paymentpreimagewaitinv0' + ('01' * 21),
    'payment_preimage_wi_2': 'paymentpreimagewaitinv0' + ('02' * 21),
    'payment_preimage_di_1': 'paymentpreimagedelinv01' + ('01' * 21),
    'payment_preimage_dp_1': 'paymentpreimgdp1' + ('01' * 24),
    'payment_preimage_xp_1': 'paymentpreimgxp1' + ('01' * 24),
    'payment_preimage_xp_2': 'paymentpreimgxp2' + ('02' * 24),
    'payment_preimage_io_1': 'paymentpreimgio1' + ('03' * 24),
    'payment_secret_l11': 'paymentsecretinvl00' + ('11000' * 9),
    'payment_secret_l22': 'paymentsecretinvl00' + ('22000' * 9),
    'payment_secret_l31': 'paymentsecretinvl00' + ('31000' * 9),
    'init_psbt_1': 'cHNidP8BAgpsbt10' + ('01' * 52),
    'init_psbt_2': 'cHNidP8BAgpsbt20' + ('02' * 84),
    'init_psbt_3': 'cHNidP8BAgpsbt30' + ('03' * 92),
    'upgrade_psbt_1': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('110000' * 100),
    'psbt_1': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('711000' * 120),
    'psbt_2': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('712000' * 120),
    'psbt_3': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('713000' * 120),
    'psbt_4': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('714000' * 120),
    'psbt_5_1': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('715100' * 120),
    'psbt_5_2': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('715200' * 120),
    'psbt_6_1': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('716100' * 120),
    'psbt_6_2': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('716200' * 120),
    'psbt_7': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('911000' * 40),
    'psbt_8': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('922000' * 40),
    'psbt_9': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('101000' * 40),
    'psbt_10': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('201000' * 40),
    'psbt_12': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('401000' * 40),
    'psbt_13': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('310000' * 40),
    'psbt_14': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('410000' * 40),
    'psbt_15': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('510000' * 40),
    'psbt_16': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('520000' * 40),
    'psbt_17': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('610000' * 40),
    'psbt_18': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('710000' * 40),
    'psbt_19': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('810000' * 40),
    'psbt_20': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('910000' * 40),
    'psbt_21': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('101000' * 40),
    'psbt_22': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('111000' * 40),
    'psbt_23': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('121000' * 40),
    'psbt_24': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('011100' * 40),
    'psbt_25': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('011200' * 40),
    'psbt_26': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('022200' * 40),
    'signed_psbt_1': 'cHNidP8BAgQCAAAAAQMEbwAAAAEEAQpsbt' + ('718000' * 120),
    'htlc_max_msat': 18446744073709552000,
}

# Used for collecting values from responses and replace them with NEW_VALUES_LIST before updating examples in schema files
REPLACE_RESPONSE_VALUES = [
    {'data_keys': ['any'], 'original_value': re.compile(re.escape(CWD)), 'new_value': NEW_VALUES_LIST['root_dir']},
    {'data_keys': ['any'], 'original_value': re.compile(r'/tmp/ltests-[^/]+/test_generate_examples_[^/]+/lightning-[^/]+'), 'new_value': NEW_VALUES_LIST['tmp_dir']},
    {'data_keys': ['outnum', 'funding_outnum', 'vout'], 'original_value': '0', 'new_value': NEW_VALUES_LIST['str_1']},
    {'data_keys': ['outnum', 'funding_outnum', 'vout'], 'original_value': 0, 'new_value': NEW_VALUES_LIST['num_1']},
    {'data_keys': ['outnum', 'funding_outnum', 'vout'], 'original_value': 2, 'new_value': NEW_VALUES_LIST['num_1']},
    {'data_keys': ['outnum', 'funding_outnum', 'vout'], 'original_value': 3, 'new_value': NEW_VALUES_LIST['num_1']},
    {'data_keys': ['type'], 'original_value': 'unilateral', 'new_value': 'mutual'},
]

if os.path.exists(LOG_FILE):
    open(LOG_FILE, 'w').close()

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%H:%M:%S',
                    handlers=[
                        logging.FileHandler(LOG_FILE),
                        logging.StreamHandler()
                    ])

logger = logging.getLogger(__name__)


class MissingExampleError(Exception):
    pass


def update_list_responses(data, list_key=None, slice_upto=5, update_func=None, sort=False, sort_key=None):
    """Update responses received from various list rpcs to limit the number of items in the list, sort the list and update the values in the list"""
    if list_key is not None:
        if isinstance(data[list_key], list):
            data[list_key] = data[list_key][0:slice_upto]

        if sort:
            data[list_key] = sorted(data[list_key], key=lambda x: x[sort_key]) if sort_key is not None else {k: data[list_key][k] for k in sorted(data[list_key])}

        if update_func is not None and isinstance(data[list_key], list):
            for i, item in enumerate(data[list_key]):
                update_func(item, i)
    return data


def replace_values_in_json(data, data_key):
    """Replace values in JSON data with new values before saving them in the schema files"""
    if isinstance(data, dict):
        return {key: replace_values_in_json(value, key) for key, value in data.items()}
    elif isinstance(data, list):
        for replace_value in REPLACE_RESPONSE_VALUES:
            if any(item == 'any' or item == data_key for item in replace_value['data_keys']) and data == replace_value['original_value']:
                data = replace_value['new_value']
                return data
        return [replace_values_in_json(item, 'listitem') for item in data]
    elif isinstance(data, str):
        for replace_value in REPLACE_RESPONSE_VALUES:
            if any(item == data_key for item in replace_value['data_keys']) and data == replace_value['original_value']:
                data = replace_value['new_value']
                break
            elif any(item == 'any' for item in replace_value['data_keys']) and isinstance(replace_value['original_value'], str) and data == replace_value['original_value']:
                data = data.replace(replace_value['original_value'], replace_value['new_value'])
                break
            elif replace_value['data_keys'] == ['any'] and isinstance(replace_value['original_value'], re.Pattern):
                if re.match(replace_value['original_value'], data):
                    data = replace_value['original_value'].sub(replace_value['new_value'], data)
                    break
        return data
    elif isinstance(data, (int, float)):
        for replace_value in REPLACE_RESPONSE_VALUES:
            if any(item == 'any' or item == data_key for item in replace_value['data_keys']) and data == replace_value['original_value']:
                data = replace_value['new_value']
                break
        return data
    else:
        return data


def update_examples_in_schema_files():
    """Update examples in JSON schema files"""
    try:
        # For testing
        if os.path.exists(TEMP_EXAMPLES_FILE):
            open(TEMP_EXAMPLES_FILE, 'w').close()
        with open(TEMP_EXAMPLES_FILE, 'w+', encoding='utf-8') as file:
            json.dump({'new_values_list': NEW_VALUES_LIST, 'replace_response_values': REPLACE_RESPONSE_VALUES[4:], 'examples_json': EXAMPLES_JSON}, file, indent=2, ensure_ascii=False)

        updated_examples = {}
        for method, method_examples in EXAMPLES_JSON.items():
            try:
                global CWD
                file_path = os.path.join(CWD, 'doc', 'schemas', f'lightning-{method}.json') if method != 'sql' else os.path.join(CWD, 'doc', 'schemas', f'lightning-{method}-template.json')
                logger.info(f'Updating examples for {method} in file {file_path}')
                with open(file_path, 'r+', encoding='utf-8') as file:
                    data = json.load(file)
                    updated_examples[method] = replace_values_in_json(method_examples, 'examples')['examples']
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

    # For testing
    if os.path.exists(TEMP_EXAMPLES_FILE):
        open(TEMP_EXAMPLES_FILE, 'w').close()
    with open(TEMP_EXAMPLES_FILE, 'w+', encoding='utf-8') as file:
        json.dump({'new_values_list': NEW_VALUES_LIST, 'replace_response_values': REPLACE_RESPONSE_VALUES[4:], 'examples_json': EXAMPLES_JSON, 'updated_examples_json': updated_examples}, file, indent=2, ensure_ascii=False)

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
                'may_reconnect': True,
                'dev-hsmd-no-preapprove-check': None,
                'dev-no-plugin-checksum': None,
                'dev-no-version-checks': None,
                'allow-deprecated-apis': True,
                'allow_bad_gossip': True,
                'broken_log': '.*',
                'dev-bitcoind-poll': 3,    # Default 1; increased to avoid rpc failures
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
        upgrade_res2 = update_example(node=l1, method='upgradewallet', params={'feerate': 'urgent', 'reservedok': True})

        # Fund node wallets for further transactions
        fund_nodes = [l1, l2, l3, l4, l5]
        for node in fund_nodes:
            node.fundwallet(FUND_WALLET_AMOUNT_SAT)
        # Connect nodes and fund channels
        getinfo_res2 = update_example(node=l2, method='getinfo', params={})
        update_example(node=l1, method='connect', params={'id': l2.info['id'], 'host': 'localhost', 'port': l2.daemon.port})
        update_example(node=l2, method='connect', params={'id': l3.info['id'], 'host': 'localhost', 'port': l3.daemon.port})
        l3.rpc.connect(l4.info['id'], 'localhost', l4.port)
        l2.rpc.connect(l5.info['id'], 'localhost', l5.port)
        c12, c12res = l1.fundchannel(l2, FUND_CHANNEL_AMOUNT_SAT)
        c23, c23res = l2.fundchannel(l3, FUND_CHANNEL_AMOUNT_SAT)
        c34, c34res = l3.fundchannel(l4, FUND_CHANNEL_AMOUNT_SAT)
        c25, c25res = l2.fundchannel(l5, announce_channel=False)
        mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])
        l1.wait_channel_active(c12)
        l1.wait_channel_active(c23)
        l1.wait_channel_active(c34)
        # Balance these newly opened channels
        l1.rpc.pay(l2.rpc.invoice('500000sat', 'lbl balance l1 to l2', 'description send some sats l1 to l2')['bolt11'])
        l2.rpc.pay(l3.rpc.invoice('500000sat', 'lbl balance l2 to l3', 'description send some sats l2 to l3')['bolt11'])
        l2.rpc.pay(l5.rpc.invoice('500000sat', 'lbl balance l2 to l5', 'description send some sats l2 to l5')['bolt11'])
        l3.rpc.pay(l4.rpc.invoice('500000sat', 'lbl balance l3 to l4', 'description send some sats l3 to l4')['bolt11'])
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['any', 'id', 'pubkey', 'destination'], 'original_value': l1.info['id'], 'new_value': NEW_VALUES_LIST['l1_id']},
            {'data_keys': ['any', 'id', 'pubkey', 'destination'], 'original_value': l2.info['id'], 'new_value': NEW_VALUES_LIST['l2_id']},
            {'data_keys': ['any', 'id', 'pubkey', 'destination'], 'original_value': l3.info['id'], 'new_value': NEW_VALUES_LIST['l3_id']},
            {'data_keys': ['any', 'id', 'pubkey', 'destination'], 'original_value': l4.info['id'], 'new_value': NEW_VALUES_LIST['l4_id']},
            {'data_keys': ['any', 'id', 'pubkey', 'destination'], 'original_value': l5.info['id'], 'new_value': NEW_VALUES_LIST['l5_id']},
            {'data_keys': ['alias'], 'original_value': l1.info['alias'], 'new_value': NEW_VALUES_LIST['l1_alias']},
            {'data_keys': ['netaddr'], 'original_value': [f'127.0.0.1:{l1.info["binding"][0]["port"]}'], 'new_value': [NEW_VALUES_LIST['l1_addr']]},
            {'data_keys': ['alias'], 'original_value': l2.info['alias'], 'new_value': NEW_VALUES_LIST['l2_alias']},
            {'data_keys': ['port'], 'original_value': l2.info['binding'][0]['port'], 'new_value': NEW_VALUES_LIST['l2_port']},
            {'data_keys': ['netaddr'], 'original_value': [f'127.0.0.1:{l2.info["binding"][0]["port"]}'], 'new_value': [NEW_VALUES_LIST['l2_addr']]},
            {'data_keys': ['version'], 'original_value': getinfo_res2['version'], 'new_value': CLN_VERSION},
            {'data_keys': ['blockheight'], 'original_value': getinfo_res2['blockheight'], 'new_value': NEW_VALUES_LIST['blockheight_110']},
            {'data_keys': ['alias'], 'original_value': l3.info['alias'], 'new_value': NEW_VALUES_LIST['l3_alias']},
            {'data_keys': ['port'], 'original_value': l3.info['binding'][0]['port'], 'new_value': NEW_VALUES_LIST['l3_port']},
            {'data_keys': ['addr'], 'original_value': f'127.0.0.1:{l3.info["binding"][0]["port"]}', 'new_value': NEW_VALUES_LIST['l3_addr']},
            {'data_keys': ['netaddr'], 'original_value': [f'127.0.0.1:{l3.info["binding"][0]["port"]}'], 'new_value': [NEW_VALUES_LIST['l3_addr']]},
            {'data_keys': ['alias'], 'original_value': l4.info['alias'], 'new_value': NEW_VALUES_LIST['l4_alias']},
            {'data_keys': ['netaddr'], 'original_value': [f'127.0.0.1:{l4.info["binding"][0]["port"]}'], 'new_value': [NEW_VALUES_LIST['l4_addr']]},
            {'data_keys': ['any', 'scid', 'channel', 'short_channel_id', 'in_channel'], 'original_value': c12, 'new_value': NEW_VALUES_LIST['c12']},
            {'data_keys': ['netaddr'], 'original_value': [f'127.0.0.1:{l5.info["binding"][0]["port"]}'], 'new_value': [NEW_VALUES_LIST['l5_addr']]},
            {'data_keys': ['netaddr'], 'original_value': [f'127.0.0.1:{l6.info["binding"][0]["port"]}'], 'new_value': [NEW_VALUES_LIST['l6_addr']]},
            {'data_keys': ['txid', 'funding_txid'], 'original_value': c12res['txid'], 'new_value': NEW_VALUES_LIST['c12_txid']},
            {'data_keys': ['channel_id', 'account'], 'original_value': c12res['channel_id'], 'new_value': NEW_VALUES_LIST['c12_channel_id']},
            {'data_keys': ['scid', 'channel', 'short_channel_id', 'id', 'out_channel'], 'original_value': c23, 'new_value': NEW_VALUES_LIST['c23']},
            {'data_keys': ['txid'], 'original_value': c23res['txid'], 'new_value': NEW_VALUES_LIST['c23_txid']},
            {'data_keys': ['channel_id', 'account', 'origin', 'originating_account'], 'original_value': c23res['channel_id'], 'new_value': NEW_VALUES_LIST['c23_channel_id']},
            {'data_keys': ['scid', 'channel', 'short_channel_id'], 'original_value': c34, 'new_value': NEW_VALUES_LIST['c34']},
            {'data_keys': ['txid'], 'original_value': c34res['txid'], 'new_value': NEW_VALUES_LIST['c34_txid']},
            {'data_keys': ['channel_id', 'account', 'origin'], 'original_value': c34res['channel_id'], 'new_value': NEW_VALUES_LIST['c34_channel_id']},
            {'data_keys': ['scid', 'channel', 'short_channel_id', 'id'], 'original_value': c25, 'new_value': NEW_VALUES_LIST['c25']},
            {'data_keys': ['channel_id', 'account'], 'original_value': c25res['channel_id'], 'new_value': NEW_VALUES_LIST['c25_channel_id']},
            {'data_keys': ['tx'], 'original_value': upgrade_res2['tx'], 'new_value': NEW_VALUES_LIST['upgrade_tx']},
            {'data_keys': ['txid'], 'original_value': upgrade_res2['txid'], 'new_value': NEW_VALUES_LIST['upgrade_txid']},
            {'data_keys': ['initialpsbt', 'psbt', 'signed_psbt'], 'original_value': upgrade_res2['psbt'], 'new_value': NEW_VALUES_LIST['upgrade_psbt_1']},
        ])
        return l1, l2, l3, l4, l5, l6, c12, c23, c25
    except Exception as e:
        logger.error(f'Error in setting up nodes: {e}')
        raise


def generate_transactions_examples(l1, l2, l3, l4, l5, c25, bitcoind):
    """Generate examples for various transactions and forwards"""
    try:
        logger.info('Simple Transactions Start...')
        global FUND_CHANNEL_AMOUNT_SAT
        # Simple Transactions by creating invoices, paying invoices, keysends
        inv_l31 = update_example(node=l3, method='invoice', params={'amount_msat': 10**4, 'label': 'lbl_l31', 'description': 'Invoice description l31'})
        route_l1_l3 = update_example(node=l1, method='getroute', params={'id': l3.info['id'], 'amount_msat': 10**4, 'riskfactor': 1})['route']
        inv_l32 = update_example(node=l3, method='invoice', params={'amount_msat': '50000msat', 'label': 'lbl_l32', 'description': 'l32 description'})
        update_example(node=l2, method='getroute', params={'id': l4.info['id'], 'amount_msat': 500000, 'riskfactor': 10, 'cltv': 9})['route']
        sendpay_res1 = update_example(node=l1, method='sendpay', params={'route': route_l1_l3, 'payment_hash': inv_l31['payment_hash'], 'payment_secret': inv_l31['payment_secret']})
        waitsendpay_res1 = update_example(node=l1, method='waitsendpay', params={'payment_hash': inv_l31['payment_hash']})
        keysend_res1 = update_example(node=l1, method='keysend', params={'destination': l3.info['id'], 'amount_msat': 10000})
        keysend_res2 = update_example(node=l1, method='keysend', params={'destination': l4.info['id'], 'amount_msat': 10000000, 'extratlvs': {'133773310': '68656c6c6f776f726c64', '133773312': '66696c7465726d65'}})
        scid = only_one([channel for channel in l2.rpc.listpeerchannels()['channels'] if channel['peer_id'] == l3.info['id']])['alias']['remote']
        routehints = [[{
            'scid': scid,
            'id': l2.info['id'],
            'feebase': '1msat',
            'feeprop': 10,
            'expirydelta': 9,
        }]]
        example_routehints = [[{
            'scid': NEW_VALUES_LIST['c23'],
            'id': NEW_VALUES_LIST['l2_id'],
            'feebase': '1msat',
            'feeprop': 10,
            'expirydelta': 9,
        }]]
        keysend_res3 = update_example(node=l1, method='keysend', params={'destination': l3.info['id'], 'amount_msat': 10000, 'routehints': routehints})
        inv_l11 = l1.rpc.invoice('10000msat', 'lbl_l11', 'l11 description')
        inv_l21 = l2.rpc.invoice('any', 'lbl_l21', 'l21 description')
        inv_l22 = l2.rpc.invoice('200000msat', 'lbl_l22', 'l22 description')
        inv_l33 = l3.rpc.invoice('100000msat', 'lbl_l33', 'l33 description')
        inv_l34 = l3.rpc.invoice(4000, 'failed', 'failed description')
        pay_res1 = update_example(node=l1, method='pay', params=[inv_l32['bolt11']])
        pay_res2 = update_example(node=l2, method='pay', params={'bolt11': inv_l33['bolt11']})

        inv_l41 = l4.rpc.invoice('10000msat', 'test_xpay_simple', 'test_xpay_simple bolt11')
        xpay_res1 = update_example(node=l1, method='xpay', params=[inv_l41['bolt11']])
        offer_l11 = l1.rpc.offer('any')
        inv_l14 = l1.rpc.fetchinvoice(offer_l11['bolt12'], '1000msat')
        xpay_res2 = update_example(node=l1, method='xpay', params={'invstring': inv_l14['invoice']})

        blockheight = l1.rpc.getinfo()['blockheight']
        amt = 10**3
        route = l1.rpc.getroute(l4.info['id'], amt, 10)['route']
        inv = l4.rpc.invoice(amt, "lbl l4", "desc l4")
        first_hop = route[0]
        sendonion_hops = []
        example_hops = []
        i = 1
        for h, n in zip(route[:-1], route[1:]):
            sendonion_hops.append({'pubkey': h['id'], 'payload': serialize_payload_tlv(amt, 18 + 6, n['channel'], blockheight).hex()})
            example_hops.append({'pubkey': NEW_VALUES_LIST['l2_id'] if i == 1 else NEW_VALUES_LIST['l3_id'], 'payload': 'payload0' + ((str(i) + '0') * 13)})
            i += 1
        sendonion_hops.append({'pubkey': route[-1]['id'], 'payload': serialize_payload_final_tlv(amt, 18, amt, blockheight, inv['payment_secret']).hex()})
        example_hops.append({'pubkey': NEW_VALUES_LIST['l4_id'], 'payload': 'payload0' + ((str(i) + '0') * 13)})
        onion_res1 = update_example(node=l1, method='createonion', params={'hops': sendonion_hops, 'assocdata': inv['payment_hash']})
        onion_res2 = update_example(node=l1, method='createonion', params={'hops': sendonion_hops, 'assocdata': inv['payment_hash'], 'session_key': '41' * 32})
        sendonion_res1 = update_example(node=l1, method='sendonion', params={'onion': onion_res1['onion'], 'first_hop': first_hop, 'payment_hash': inv['payment_hash']})

        # Close channels examples
        close_res1 = update_example(node=l2, method='close', params={'id': l3.info['id'], 'unilateraltimeout': 1})
        address_l41 = l4.rpc.newaddr()
        close_res2 = update_example(node=l3, method='close', params={'id': l4.info['id'], 'destination': address_l41['bech32']})
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
        signinv_res1 = update_example(node=l2, method='signinvoice', params={'invstring': inv_l12['bolt11']})
        signinv_res2 = update_example(node=l3, method='signinvoice', params=[inv_l26['bolt11']])
        update_example(node=l1, method='preapprovekeysend', params={'destination': l2.info['id'], 'payment_hash': '00' * 32, 'amount_msat': 1000})
        update_example(node=l5, method='preapprovekeysend', params=[l5.info['id'], '01' * 32, 2000])
        update_example(node=l1, method='preapproveinvoice', params={'bolt11': inv_l24['bolt11']})
        update_example(node=l1, method='preapproveinvoice', params=[inv_l25['bolt11']])
        inv_req = update_example(node=l2, method='invoicerequest', params={'amount': 1000000, 'description': 'Simple test'})
        sendinvoice_res1 = update_example(node=l1, method='sendinvoice', params={'invreq': inv_req['bolt12'], 'label': 'test sendinvoice'})
        inv_l13 = l1.rpc.invoice(amount_msat=100000, label='lbl_l13', description='l13 description', preimage='01' * 32)
        createinv_res1 = update_example(node=l2, method='createinvoice', params={'invstring': inv_l13['bolt11'], 'label': 'lbl_l13', 'preimage': '01' * 32})
        inv_l27 = l2.rpc.invoice(amt, 'test_injectpaymentonion1', 'test injectpaymentonion1 description')
        injectpaymentonion_hops = [
            {'pubkey': l1.info['id'],
             'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
            {'pubkey': l2.info['id'],
             'payload': serialize_payload_final_tlv(1000, 18, 1000, blockheight, inv_l27['payment_secret']).hex()}]
        onion_res3 = l1.rpc.createonion(hops=injectpaymentonion_hops, assocdata=inv_l27['payment_hash'])
        injectpaymentonion_res1 = update_example(node=l1, method='injectpaymentonion', params={
            'onion': onion_res3['onion'],
            'payment_hash': inv_l27['payment_hash'],
            'amount_msat': 1000,
            'cltv_expiry': blockheight + 18 + 6,
            'partid': 1,
            'groupid': 0})
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['destination'], 'original_value': address_l41['bech32'], 'new_value': NEW_VALUES_LIST['destination_6']},
            {'data_keys': ['tx'], 'original_value': close_res1['tx'], 'new_value': NEW_VALUES_LIST['close1_tx']},
            {'data_keys': ['txs'], 'original_value': close_res1['txs'], 'new_value': [NEW_VALUES_LIST['close1_tx']]},
            {'data_keys': ['txid', 'spending_txid'], 'original_value': close_res1['txid'], 'new_value': NEW_VALUES_LIST['close1_txid']},
            {'data_keys': ['txids'], 'original_value': close_res1['txids'], 'new_value': [NEW_VALUES_LIST['close1_txid']]},
            {'data_keys': ['tx'], 'original_value': close_res2['tx'], 'new_value': NEW_VALUES_LIST['close2_tx']},
            {'data_keys': ['txs'], 'original_value': close_res2['txs'], 'new_value': [NEW_VALUES_LIST['close2_tx']]},
            {'data_keys': ['txid'], 'original_value': close_res2['txid'], 'new_value': NEW_VALUES_LIST['close2_txid']},
            {'data_keys': ['txids'], 'original_value': close_res2['txids'], 'new_value': [NEW_VALUES_LIST['close2_txid']]},
            {'data_keys': ['any', 'bolt11'], 'original_value': createinv_res1['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l21']},
            {'data_keys': ['payment_hash'], 'original_value': createinv_res1['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l21']},
            {'data_keys': ['expires_at'], 'original_value': createinv_res1['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l31['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l31']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l31['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l31']},
            {'data_keys': ['payment_secret'], 'original_value': inv_l31['payment_secret'], 'new_value': NEW_VALUES_LIST['payment_secret_l31']},
            {'data_keys': ['expires_at'], 'original_value': inv_l31['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l32['payment_hash'], 'new_value': 'paymenthashinvl0' + ('3200' * 12)},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l32['bolt11'], 'new_value': 'lnbcrt100n1pnt2' + ('bolt11invl032000000000' * 10)},
            {'data_keys': ['payment_secret'], 'original_value': inv_l32['payment_secret'], 'new_value': 'paymentsecretinvl000' + ('3200' * 11)},
            {'data_keys': ['expires_at'], 'original_value': inv_l32['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l11['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l11']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l11['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l11']},
            {'data_keys': ['payment_secret'], 'original_value': inv_l11['payment_secret'], 'new_value': NEW_VALUES_LIST['payment_secret_l11']},
            {'data_keys': ['expires_at'], 'original_value': inv_l11['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l21['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l21']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l21['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l21']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l22['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l22']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l22['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l22']},
            {'data_keys': ['payment_secret'], 'original_value': inv_l22['payment_secret'], 'new_value': NEW_VALUES_LIST['payment_secret_l22']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l33['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l33']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l33['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l33']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l34['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l34']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l34['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l34']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l41['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l41']},
            {'data_keys': ['invstring'], 'original_value': inv_l14['invoice'], 'new_value': NEW_VALUES_LIST['invoice_3']},
            {'data_keys': ['hops'], 'original_value': sendonion_hops, 'new_value': example_hops},
            {'data_keys': ['any', 'assocdata'], 'original_value': inv['payment_hash'], 'new_value': NEW_VALUES_LIST['assocdata_1']},
            {'data_keys': ['onion'], 'original_value': onion_res1['onion'], 'new_value': NEW_VALUES_LIST['onion_1']},
            {'data_keys': ['shared_secrets'], 'original_value': onion_res1['shared_secrets'], 'new_value': NEW_VALUES_LIST['shared_secrets_1']},
            {'data_keys': ['any', 'onion'], 'original_value': onion_res2['onion'], 'new_value': NEW_VALUES_LIST['onion_2']},
            {'data_keys': ['shared_secrets'], 'original_value': onion_res2['shared_secrets'], 'new_value': NEW_VALUES_LIST['shared_secrets_2']},
            {'data_keys': ['onion'], 'original_value': onion_res3['onion'], 'new_value': NEW_VALUES_LIST['onion_3']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l27['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l27']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l27['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l27']},
            {'data_keys': ['payment_preimage'], 'original_value': injectpaymentonion_res1['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_io_1']},
            {'data_keys': ['created_at'], 'original_value': injectpaymentonion_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['completed_at'], 'original_value': injectpaymentonion_res1['completed_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['id', 'scid', 'channel', 'short_channel_id', 'out_channel'], 'original_value': c23_2, 'new_value': NEW_VALUES_LIST['c23_2']},
            {'data_keys': ['txid'], 'original_value': c23res2['txid'], 'new_value': NEW_VALUES_LIST['c23_2_txid']},
            {'data_keys': ['any', 'channel_id', 'account'], 'original_value': c23res2['channel_id'], 'new_value': NEW_VALUES_LIST['c23_2_channel_id']},
            {'data_keys': ['scid', 'channel', 'short_channel_id'], 'original_value': c34_2, 'new_value': NEW_VALUES_LIST['c34_2']},
            {'data_keys': ['txid'], 'original_value': c34res2['txid'], 'new_value': NEW_VALUES_LIST['c34_2_txid']},
            {'data_keys': ['channel_id', 'account'], 'original_value': c34res2['channel_id'], 'new_value': NEW_VALUES_LIST['c34_2_channel_id']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l12['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l12']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l24['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l24']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l24['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l24']},
            {'data_keys': ['expires_at'], 'original_value': inv_l24['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l25['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l25']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l25['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l25']},
            {'data_keys': ['payment_hash'], 'original_value': inv_l26['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_l26']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l26['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l26']},
            {'data_keys': ['any', 'invstring', 'bolt11'], 'original_value': inv_l13['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l13']},
            {'data_keys': ['invreq_id'], 'original_value': inv_req['invreq_id'], 'new_value': NEW_VALUES_LIST['invreq_id_1']},
            {'data_keys': ['any', 'bolt12', 'invreq'], 'original_value': inv_req['bolt12'], 'new_value': NEW_VALUES_LIST['bolt12_l21']},
            {'data_keys': ['payment_hash'], 'original_value': keysend_res1['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_key_1']},
            {'data_keys': ['created_at'], 'original_value': keysend_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['payment_preimage'], 'original_value': keysend_res1['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_1']},
            {'data_keys': ['payment_hash'], 'original_value': keysend_res2['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_key_2']},
            {'data_keys': ['created_at'], 'original_value': keysend_res2['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['payment_preimage'], 'original_value': keysend_res2['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_2']},
            {'data_keys': ['payment_hash'], 'original_value': keysend_res3['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_key_3']},
            {'data_keys': ['created_at'], 'original_value': keysend_res3['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['payment_preimage'], 'original_value': keysend_res3['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_3']},
            {'data_keys': ['routehints'], 'original_value': routehints, 'new_value': example_routehints},
            {'data_keys': ['created_at'], 'original_value': pay_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['payment_preimage'], 'original_value': pay_res1['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_ep_1']},
            {'data_keys': ['created_at'], 'original_value': pay_res2['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['payment_preimage'], 'original_value': pay_res2['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_ep_2']},
            {'data_keys': ['any', 'bolt12', 'invreq'], 'original_value': sendinvoice_res1['bolt12'], 'new_value': NEW_VALUES_LIST['bolt12_si_1']},
            {'data_keys': ['payment_hash'], 'original_value': sendinvoice_res1['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_si_1']},
            {'data_keys': ['payment_preimage'], 'original_value': sendinvoice_res1['payment_preimage'], 'new_value': NEW_VALUES_LIST['payments_preimage_i_1']},
            {'data_keys': ['paid_at'], 'original_value': sendinvoice_res1['paid_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['expires_at'], 'original_value': sendinvoice_res1['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['created_at'], 'original_value': sendonion_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['created_at'], 'original_value': sendpay_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['any', 'bolt11'], 'original_value': signinv_res1['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l66']},
            {'data_keys': ['any', 'bolt11'], 'original_value': signinv_res2['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l67']},
            {'data_keys': ['payment_preimage'], 'original_value': waitsendpay_res1['payment_preimage'], 'new_value': NEW_VALUES_LIST['payments_preimage_w_1']},
            {'data_keys': ['created_at'], 'original_value': waitsendpay_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['completed_at'], 'original_value': waitsendpay_res1['completed_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['payment_preimage'], 'original_value': xpay_res1['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_xp_1']},
            {'data_keys': ['payment_preimage'], 'original_value': xpay_res2['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_xp_2']},
        ])
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
        update_example(node=l2, method='commando-listrunes', params={'rune': rune_l23['rune']})
        update_example(node=l2, method='commando-listrunes', params={})
        commando_res1 = update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l21['rune'], 'method': 'newaddr', 'params': {'addresstype': 'p2tr'}})
        update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l23['rune'], 'method': 'listpeers', 'params': [l3.info['id']]})
        inv_l23 = l2.rpc.invoice('any', 'lbl_l23', 'l23 description')
        commando_res3 = update_example(node=l1, method='commando', params={'peer_id': l2.info['id'], 'rune': rune_l24['rune'], 'method': 'pay', 'params': {'bolt11': inv_l23['bolt11'], 'amount_msat': 9900}})
        update_example(node=l2, method='checkrune', params={'nodeid': l2.info['id'], 'rune': rune_l22['rune'], 'method': 'listpeers', 'params': {}})
        update_example(node=l2, method='checkrune', params={'nodeid': l2.info['id'], 'rune': rune_l24['rune'], 'method': 'pay', 'params': {'amount_msat': 9999}})
        showrunes_res1 = update_example(node=l2, method='showrunes', params={'rune': rune_l21['rune']})
        showrunes_res2 = update_example(node=l2, method='showrunes', params={})
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
                                    '2: `[\'method/listdatastore\']`: But not listdatastore: that contains sensitive stuff!'])
        update_example(node=l1, method='commando-rune', params={'rune': rune_l11['rune'], 'restrictions': [['method^list', 'method^get', 'method=summary'], ['method/listdatastore']]}, description=['We can do the same manually (readonly), like so:'])
        update_example(node=l1, method='commando-rune', params={'restrictions': [[f'id^{trimmed_id}'], ['method=listpeers']]}, description=[f'This will allow the rune to be used for id starting with {trimmed_id}, and for the method listpeers:'])
        update_example(node=l1, method='commando-rune', params={'restrictions': [['method=pay'], ['pnameamountmsat<10000']]}, description=['This will allow the rune to be used for the method pay, and for the parameter amount\\_msat to be less than 10000:'])
        update_example(node=l1, method='commando-rune', params={'restrictions': [[f'id={l1.info["id"]}'], ['method=listpeers'], ['pnum=1'], [f'pnameid={l1.info["id"]}', f'parr0={l1.info["id"]}']]}, description=["Let's create a rune which lets a specific peer run listpeers on themselves:"])
        rune_l15 = update_example(node=l1, method='commando-rune', params={'restrictions': [[f'id={l1.info["id"]}'], ['method=listpeers'], ['pnum=1'], [f'pnameid^{trimmed_id}', f'parr0^{trimmed_id}']]}, description=["This allows `listpeers` with 1 argument (`pnum=1`), which is either by name (`pnameid`), or position (`parr0`). We could shorten this in several ways: either allowing only positional or named parameters, or by testing the start of the parameters only. Here's an example which only checks the first 10 bytes of the `listpeers` parameter:"])
        update_example(node=l1, method='commando-rune', params=[rune_l15['rune'], [['time<"$(($(date +%s) + 24*60*60))"', 'rate=2']]], description=["Before we give this to our peer, let's add two more restrictions: that it only be usable for 24 hours from now (`time<`), and that it can only be used twice a minute (`rate=2`). `date +%s` can give us the current time in seconds:"])
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['last_used'], 'original_value': showrunes_res1['runes'][0]['last_used'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['last_used'], 'original_value': showrunes_res2['runes'][1]['last_used'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['last_used'], 'original_value': showrunes_res2['runes'][2]['last_used'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['any', 'bolt11'], 'original_value': inv_l23['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_l23']},
            {'data_keys': ['p2tr'], 'original_value': commando_res1['p2tr'], 'new_value': NEW_VALUES_LIST['destination_7']},
            {'data_keys': ['created_at'], 'original_value': commando_res3['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['payment_hash'], 'original_value': commando_res3['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_cmd_pay_1']},
            {'data_keys': ['payment_preimage'], 'original_value': commando_res3['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_cmd_1']},
        ])
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
        bkprinspect_res1 = update_example(node=l2, method='bkpr-inspect', params={'account': c23_2_chan_id})
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
        editdescriptionbyoutpoint_res1 = update_example(node=l3, method='bkpr-editdescriptionbyoutpoint', params={'outpoint': utxo_event['outpoint'], 'description': 'edited utxo description'})
        # Try to edit an outpoint that does not exist
        update_example(node=l3, method='bkpr-editdescriptionbyoutpoint', params={'outpoint': 'abcd' + ('02' * 30) + ':1', 'description': 'edited utxo description for non existing outpoint'})

        bkprlistbal_res1 = update_example(node=l3, method='bkpr-listbalances', params={})

        bkprlistaccountevents_res1 = l3.rpc.bkpr_listaccountevents(c23_2_chan_id)
        bkprlistaccountevents_res1['events'] = [next((event for event in bkprlistaccountevents_res1['events'] if event['tag'] == 'channel_open'), None)]
        bkprlistaccountevents_res1 = update_list_responses(bkprlistaccountevents_res1, list_key='events')
        update_example(node=l3, method='bkpr-listaccountevents', params=[c23_2_chan_id], response=bkprlistaccountevents_res1)
        bkprlistaccountevents_res2 = l3.rpc.bkpr_listaccountevents()
        external_event = None
        wallet_event = None
        channel_event = None
        for bkprevent in bkprlistaccountevents_res2['events']:
            event_seleted = None
            if wallet_event is None and bkprevent['account'] == 'wallet':
                bkprevent['blockheight'] = 141
                wallet_event = bkprevent
                event_seleted = '01'
            elif external_event is None and bkprevent['account'] == 'external' and bkprevent['origin'] == next((value['original_value'] for value in REPLACE_RESPONSE_VALUES if value['new_value'] == NEW_VALUES_LIST['c34_channel_id']), None):
                bkprevent['blockheight'] = 142
                external_event = bkprevent
                event_seleted = '02'
            elif channel_event is None and bkprevent['account'] not in ['external', 'wallet']:
                bkprevent['blockheight'] = 143
                channel_event = bkprevent
                event_seleted = '03'
            if event_seleted is not None:
                bkpr_new_values = [
                    {'data_keys': ['timestamp'], 'original_value': bkprevent['timestamp'], 'new_value': NEW_VALUES_LIST['time_at_850'] + (int(event_seleted) * 10000)},
                ]
                if 'debit_msat' in bkprevent and bkprevent['debit_msat'] > 0:
                    bkpr_new_values.extend([
                        {'data_keys': ['debit_msat'], 'original_value': bkprevent['debit_msat'], 'new_value': 200000000000},
                    ])
                if 'txid' in bkprevent:
                    bkpr_new_values.extend([
                        {'data_keys': ['txid'], 'original_value': bkprevent['txid'], 'new_value': 'txidbk' + (event_seleted * 29)},
                    ])
                if 'outpoint' in bkprevent:
                    bkpr_new_values.extend([
                        {'data_keys': ['outpoint'], 'original_value': bkprevent['outpoint'], 'new_value': 'txidbk' + (event_seleted * 29) + ':1'},
                    ])
                if 'payment_id' in bkprevent:
                    bkpr_new_values.extend([
                        {'data_keys': ['payment_id'], 'original_value': bkprevent['payment_id'], 'new_value': 'paymentidbk0' + (event_seleted * 26)},
                    ])
                REPLACE_RESPONSE_VALUES.extend(bkpr_new_values)
            if wallet_event and external_event and channel_event:
                break
        bkprlistaccountevents_res2['events'] = [event for event in [external_event, wallet_event, channel_event] if event is not None]
        update_example(node=l3, method='bkpr-listaccountevents', params={}, response=bkprlistaccountevents_res2)
        bkprlistincome_res1 = l3.rpc.bkpr_listincome(consolidate_fees=False)
        bkprlistincome_res1 = update_list_responses(bkprlistincome_res1, list_key='income_events', slice_upto=4, update_func=lambda x, i: x.update({
            **({'timestamp': NEW_VALUES_LIST['time_at_850'] + (i * 10000)} if 'timestamp' in x else {}),
            **({'payment_id': 'paymentid000' + (f"{i:02}" * 26)} if 'payment_id' in x else {}),
            **({'outpoint': 'txidbk' + (f"{i:02}" * 29) + ':1'} if 'outpoint' in x else {})}), sort=True, sort_key='tag')
        update_example(node=l3, method='bkpr-listincome', params={'consolidate_fees': False}, response=bkprlistincome_res1)
        bkprlistincome_res2 = l3.rpc.bkpr_listincome()
        deposit_income = None
        invoice_income = None
        fee_income = None
        for bkprincome in bkprlistincome_res2['income_events']:
            income_seleted = None
            if deposit_income is None and bkprincome['tag'] == 'deposit':
                deposit_income = bkprincome
                income_seleted = 1
            elif invoice_income is None and bkprincome['tag'] == 'invoice':
                invoice_income = bkprincome
                income_seleted = 2
            elif fee_income is None and bkprincome['tag'] == 'onchain_fee' and bkprincome['txid'] == next((value['original_value'] for value in REPLACE_RESPONSE_VALUES if value['new_value'] == NEW_VALUES_LIST['c34_2_txid']), None):
                fee_income = bkprincome
                income_seleted = 3
            if income_seleted is not None:
                REPLACE_RESPONSE_VALUES.extend([
                    {'data_keys': ['timestamp'], 'original_value': bkprincome['timestamp'], 'new_value': NEW_VALUES_LIST['time_at_850'] + (income_seleted * 10000)},
                ])
                if 'debit_msat' in bkprincome and bkprincome['debit_msat'] > 0:
                    REPLACE_RESPONSE_VALUES.extend([
                        {'data_keys': ['debit_msat'], 'original_value': bkprincome['debit_msat'], 'new_value': 6960000},
                    ])
                if 'payment_id' in bkprincome:
                    REPLACE_RESPONSE_VALUES.extend([
                        {'data_keys': ['payment_id'], 'original_value': bkprincome['payment_id'], 'new_value': 'paymentid000' + (f"{income_seleted:02}" * 26)},
                    ])
                if 'outpoint' in bkprincome:
                    REPLACE_RESPONSE_VALUES.extend([
                        {'data_keys': ['outpoint'], 'original_value': bkprincome['outpoint'], 'new_value': 'txidbk' + (f"{income_seleted:02}" * 29) + ':1'},
                    ])
            if deposit_income and invoice_income and fee_income:
                break
        bkprlistincome_res2['income_events'] = [income for income in [deposit_income, invoice_income, fee_income] if income is not None]
        update_example(node=l3, method='bkpr-listincome', params={}, response=bkprlistincome_res2)
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['balance_msat'], 'original_value': bkprlistbal_res1['accounts'][0]['balances'][0]['balance_msat'], 'new_value': NEW_VALUES_LIST['balance_msat_1']},
            {'data_keys': ['fees_paid_msat'], 'original_value': bkprinspect_res1['txs'][0]['fees_paid_msat'], 'new_value': NEW_VALUES_LIST['fees_paid_msat_1']},
            {'data_keys': ['timestamp'], 'original_value': bkprlistaccountevents_res1['events'][0]['timestamp'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['outpoint'], 'original_value': bkprlistaccountevents_res1['events'][0]['outpoint'], 'new_value': 'txidbk' + ('01' * 29) + ':1'},
            {'data_keys': ['blockheight'], 'original_value': editdescriptionbyoutpoint_res1['updated'][0]['blockheight'], 'new_value': NEW_VALUES_LIST['blockheight_110']},
        ])
        logger.info('Bookkeeper Done!')
    except Exception as e:
        logger.error(f'Error in generating bookkeeper examples: {e}')
        raise


def generate_offers_renepay_examples(l1, l2, inv_l21, inv_l34):
    """Covers all offers and renepay related examples"""
    try:
        logger.info('Offers and Renepay Start...')

        # Offers & Offers Lists
        offer_l21 = update_example(node=l2, method='offer', params={'amount': '10000msat', 'description': 'Fish sale!'})
        offer_l22 = update_example(node=l2, method='offer', params={'amount': '1000sat', 'description': 'Coffee', 'quantity_max': 10})
        offer_l23 = l2.rpc.offer('2000sat', 'Offer to Disable')
        fetchinv_res1 = update_example(node=l1, method='fetchinvoice', params={'offer': offer_l21['bolt12'], 'payer_note': 'Thanks for the fish!'})
        fetchinv_res2 = update_example(node=l1, method='fetchinvoice', params={'offer': offer_l22['bolt12'], 'amount_msat': 2000000, 'quantity': 2})
        update_example(node=l2, method='disableoffer', params={'offer_id': offer_l23['offer_id']})
        update_example(node=l2, method='enableoffer', params={'offer_id': offer_l23['offer_id']})

        # Invoice Requests
        inv_req_l1_l22 = update_example(node=l2, method='invoicerequest', params={'amount': '10000sat', 'description': 'Requesting for invoice', 'issuer': 'clightning store'})
        disableinv_res1 = update_example(node=l2, method='disableinvoicerequest', params={'invreq_id': inv_req_l1_l22['invreq_id']})

        # Renepay
        renepay_res1 = update_example(node=l1, method='renepay', params={'invstring': inv_l21['bolt11'], 'amount_msat': 400000})
        renepay_res2 = update_example(node=l2, method='renepay', params={'invstring': inv_l34['bolt11']})
        update_example(node=l1, method='renepaystatus', params={'invstring': inv_l21['bolt11']})
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['offer_id'], 'original_value': offer_l21['offer_id'], 'new_value': NEW_VALUES_LIST['offerid_l21']},
            {'data_keys': ['any', 'bolt12', 'invreq'], 'original_value': offer_l21['bolt12'], 'new_value': NEW_VALUES_LIST['bolt12_l21']},
            {'data_keys': ['offer_id'], 'original_value': offer_l22['offer_id'], 'new_value': NEW_VALUES_LIST['offerid_l22']},
            {'data_keys': ['any', 'bolt12', 'invreq'], 'original_value': offer_l22['bolt12'], 'new_value': NEW_VALUES_LIST['bolt12_l22']},
            {'data_keys': ['offer_id'], 'original_value': offer_l23['offer_id'], 'new_value': NEW_VALUES_LIST['offerid_l23']},
            {'data_keys': ['any', 'bolt12', 'invreq'], 'original_value': offer_l23['bolt12'], 'new_value': NEW_VALUES_LIST['bolt12_l23']},
            {'data_keys': ['invreq_id'], 'original_value': inv_req_l1_l22['invreq_id'], 'new_value': NEW_VALUES_LIST['invreq_id_2']},
            {'data_keys': ['any', 'bolt12', 'invreq'], 'original_value': disableinv_res1['bolt12'], 'new_value': NEW_VALUES_LIST['bolt12_l24']},
            {'data_keys': ['invoice'], 'original_value': fetchinv_res1['invoice'], 'new_value': NEW_VALUES_LIST['invoice_1']},
            {'data_keys': ['invoice'], 'original_value': fetchinv_res2['invoice'], 'new_value': NEW_VALUES_LIST['invoice_2']},
            {'data_keys': ['created_at'], 'original_value': renepay_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['payment_preimage'], 'original_value': renepay_res1['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_r_1']},
            {'data_keys': ['created_at'], 'original_value': renepay_res2['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['payment_preimage'], 'original_value': renepay_res2['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_r_2']},
        ])
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
        askrene_inform_channel_res1 = update_example(node=l2, method='askrene-inform-channel', params={'layer': 'test_layers', 'short_channel_id_dir': '0x0x1/1', 'amount_msat': 100000, 'inform': 'unconstrained'})
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
        askrene_listreservations_res1 = update_list_responses(askrene_listreservations_res1, list_key='reservations', slice_upto=5, update_func=lambda x, i: REPLACE_RESPONSE_VALUES.extend([{'data_keys': ['command_id'], 'original_value': x['command_id'], 'new_value': f'\"-c:askrene-reserve#6{(i + 1) * 2}/cln:askrene-reserve#12{(i + 1) * 2}\"'}]), sort=True, sort_key='amount_msat')
        update_example(node=l1, method='askrene-listreservations', params={}, response=askrene_listreservations_res1)
        update_example(node=l1, method='askrene-unreserve', params={'path': [{'short_channel_id_dir': scid12dir, 'amount_msat': 1250_000}, {'short_channel_id_dir': scid23dir, 'amount_msat': 1250_001}]})
        update_example(node=l1, method='askrene-unreserve', params={'path': [{'short_channel_id_dir': scid12dir, 'amount_msat': 1250_000_000_000}, {'short_channel_id_dir': scid23dir, 'amount_msat': 1250_000_000_000}]})
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['any', 'short_channel_id_dir'], 'original_value': scid12dir, 'new_value': f"{NEW_VALUES_LIST['c12']}/{direction12}"},
            {'data_keys': ['short_channel_id_dir'], 'original_value': scid23dir, 'new_value': f"{NEW_VALUES_LIST['c23_2']}/{direction23}"},
            {'data_keys': ['cutoff'], 'original_value': ts1 + 1, 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['timestamp'], 'original_value': askrene_inform_channel_res1['constraints'][0]['timestamp'], 'new_value': NEW_VALUES_LIST['time_at_800']},
        ])
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
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['payment_hash'], 'original_value': wspc_res['details']['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_wspc_1']},
            {'data_keys': ['paid_at'], 'original_value': waires['paid_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['expires_at'], 'original_value': waires['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['paid_at'], 'original_value': wai_pay_index_res['paid_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['expires_at'], 'original_value': wai_pay_index_res['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['bolt11'], 'original_value': wi2res['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_wt_1']},
            {'data_keys': ['payment_hash'], 'original_value': wi2res['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_winv_1']},
            {'data_keys': ['payment_preimage'], 'original_value': wi2res['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_wi_1']},
            {'data_keys': ['paid_at'], 'original_value': wi2res['paid_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['expires_at'], 'original_value': wi2res['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['bolt11'], 'original_value': wi3res['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_wt_2']},
            {'data_keys': ['payment_hash'], 'original_value': wi3res['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_winv_2']},
            {'data_keys': ['payment_preimage'], 'original_value': wi3res['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_wi_2']},
            {'data_keys': ['paid_at'], 'original_value': wi3res['paid_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['expires_at'], 'original_value': wi3res['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
        ])
        logger.info('Wait Done!')
    except Exception as e:
        logger.error(f'Error in generating wait examples: {e}')
        raise


def generate_utils_examples(l1, l2, l3, l4, l5, l6, c23_2, c34_2, inv_l11, inv_l22, rune_l21, bitcoind):
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
        example_utxos = ['utxo' + ('02' * 30) + ':1']
        withdraw_l22 = update_example(node=l2, method='withdraw', params={'destination': address_l22['p2tr'], 'satoshi': 'all', 'feerate': '20000perkb', 'minconf': 0, 'utxos': utxos})
        bitcoind.generate_block(4, wait_for_mempool=[withdraw_l22['txid']])
        multiwithdraw_res1 = update_example(node=l2, method='multiwithdraw', params={'outputs': [{l1.rpc.newaddr()['bech32']: '2222000msat'}, {l1.rpc.newaddr()['bech32']: '3333000msat'}]})
        multiwithdraw_res2 = update_example(node=l2, method='multiwithdraw', params={'outputs': [{l1.rpc.newaddr('p2tr')['p2tr']: 1000}, {l1.rpc.newaddr()['bech32']: 1000}, {l2.rpc.newaddr()['bech32']: 1000}, {l3.rpc.newaddr()['bech32']: 1000}, {l3.rpc.newaddr()['bech32']: 1000}, {l4.rpc.newaddr('p2tr')['p2tr']: 1000}, {l1.rpc.newaddr()['bech32']: 1000}]})
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
        decodepay_res1 = update_example(node=l2, method='decodepay', params={'bolt11': inv_l11['bolt11']})
        update_example(node=l2, method='decode', params=[rune_l21['rune']])
        decode_res2 = update_example(node=l2, method='decode', params=[inv_l22['bolt11']])

        # PSBT
        amount1 = 1000000
        amount2 = 3333333
        psbtoutput_res1 = update_example(node=l1, method='addpsbtoutput', params={'satoshi': amount1, 'locktime': 111}, description=[f'Here is a command to make a PSBT with a {amount1:,} sat output that leads to the on-chain wallet:'])
        update_example(node=l1, method='setpsbtversion', params={'psbt': psbtoutput_res1['psbt'], 'version': 0})
        psbtoutput_res2 = l1.rpc.addpsbtoutput(amount2, psbtoutput_res1['psbt'])
        update_example(node=l1, method='addpsbtoutput', params=[amount2, psbtoutput_res2['psbt']], response=psbtoutput_res2)
        dest = l1.rpc.newaddr('p2tr')['p2tr']
        psbtoutput_res3 = update_example(node=l1, method='addpsbtoutput', params={'satoshi': amount2, 'initialpsbt': psbtoutput_res2['psbt'], 'destination': dest})
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
        sendpsbt_res1 = update_example(node=l1, method='sendpsbt', params={'psbt': signed_psbt})

        # SQL
        update_example(node=l1, method='sql', params={'query': 'SELECT id FROM peers'}, description=['A simple peers selection query:'])
        update_example(node=l1, method='sql', params=[f"SELECT label, description, status FROM invoices WHERE label='label inv_l12'"], description=["A statement containing `=` needs `-o` in shell:"])
        sql_res3 = l1.rpc.sql(f"SELECT nodeid FROM nodes WHERE nodeid != x'{l3.info['id']}'")
        update_example(node=l1, method='sql', params=[f"SELECT nodeid FROM nodes WHERE nodeid != x'{NEW_VALUES_LIST['l3_id']}'"], description=['If you want to get specific nodeid values from the nodes table:'], response=sql_res3)
        sql_res4 = l1.rpc.sql(f"SELECT nodeid FROM nodes WHERE nodeid IN (x'{l1.info['id']}', x'{l3.info['id']}')")
        update_example(node=l1, method='sql', params=[f"SELECT nodeid FROM nodes WHERE nodeid IN (x'{NEW_VALUES_LIST['l1_id']}', x'{NEW_VALUES_LIST['l3_id']}')"], description=["If you want to compare a BLOB column, `x'hex'` or `X'hex'` are needed:"], response=sql_res4)
        update_example(node=l1, method='sql', params=['SELECT peer_id, to_us_msat, total_msat, peerchannels_status.status FROM peerchannels INNER JOIN peerchannels_status ON peerchannels_status.row = peerchannels.rowid'], description=['Related tables are usually referenced by JOIN:'])
        update_example(node=l2, method='sql', params=['SELECT COUNT(*) FROM forwards'], description=["Simple function usage, in this case COUNT. Strings inside arrays need \", and ' to protect them from the shell:"])
        update_example(node=l1, method='sql', params=['SELECT * from peerchannels_features'])
        example_log = getlog_res1['log']
        for i, log_entry in enumerate(example_log):
            if 'num_skipped' in log_entry:
                log_entry['num_skipped'] = 144 + i
            if 'time' in log_entry:
                log_entry['time'] = f"{70.8 + i}00000000"
            if 'node_id' in log_entry:
                log_entry['node_id'] = 'nodeid' + ('01' * 30)
            if log_entry.get('log', '').startswith('No peer channel with'):
                log_entry['log'] = 'No peer channel with scid=228x1x1'
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['any', 'psbt', 'initialpsbt'], 'original_value': psbtoutput_res1['psbt'], 'new_value': NEW_VALUES_LIST['init_psbt_1']},
            {'data_keys': ['any', 'psbt', 'initialpsbt'], 'original_value': psbtoutput_res2['psbt'], 'new_value': NEW_VALUES_LIST['init_psbt_2']},
            {'data_keys': ['any', 'psbt', 'initialpsbt'], 'original_value': psbtoutput_res3['psbt'], 'new_value': NEW_VALUES_LIST['init_psbt_3']},
            {'data_keys': ['destination'], 'original_value': dest, 'new_value': NEW_VALUES_LIST['destination_1']},
            {'data_keys': ['created_at'], 'original_value': decode_res2['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['signature'], 'original_value': decode_res2['signature'], 'new_value': NEW_VALUES_LIST['signature_1']},
            {'data_keys': ['short_channel_id'], 'original_value': decode_res2['routes'][0][0]['short_channel_id'], 'new_value': NEW_VALUES_LIST['c23']},
            {'data_keys': ['created_at'], 'original_value': decodepay_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['signature'], 'original_value': decodepay_res1['signature'], 'new_value': NEW_VALUES_LIST['signature_2']},
            {'data_keys': ['tx'], 'original_value': multiwithdraw_res1['tx'], 'new_value': NEW_VALUES_LIST['tx_55']},
            {'data_keys': ['txid'], 'original_value': multiwithdraw_res1['txid'], 'new_value': NEW_VALUES_LIST['txid_55']},
            {'data_keys': ['tx'], 'original_value': multiwithdraw_res2['tx'], 'new_value': NEW_VALUES_LIST['tx_56']},
            {'data_keys': ['txid'], 'original_value': multiwithdraw_res2['txid'], 'new_value': NEW_VALUES_LIST['txid_56']},
            {'data_keys': ['psbt'], 'original_value': signed_psbt, 'new_value': NEW_VALUES_LIST['psbt_1']},
            {'data_keys': ['tx', 'hash'], 'original_value': sendpsbt_res1['tx'], 'new_value': NEW_VALUES_LIST['tx_61']},
            {'data_keys': ['txid'], 'original_value': sendpsbt_res1['txid'], 'new_value': NEW_VALUES_LIST['txid_61']},
            {'data_keys': ['destination'], 'original_value': address_l21['bech32'], 'new_value': NEW_VALUES_LIST['destination_2']},
            {'data_keys': ['destination'], 'original_value': address_l22['p2tr'], 'new_value': NEW_VALUES_LIST['destination_3']},
            {'data_keys': ['utxos'], 'original_value': utxos, 'new_value': example_utxos},
            {'data_keys': ['tx'], 'original_value': withdraw_l21['tx'], 'new_value': NEW_VALUES_LIST['tx_91']},
            {'data_keys': ['txid'], 'original_value': withdraw_l21['txid'], 'new_value': NEW_VALUES_LIST['withdraw_txid_l21']},
            {'data_keys': ['psbt'], 'original_value': withdraw_l21['psbt'], 'new_value': NEW_VALUES_LIST['psbt_7']},
            {'data_keys': ['tx'], 'original_value': withdraw_l22['tx'], 'new_value': NEW_VALUES_LIST['tx_92']},
            {'data_keys': ['txid'], 'original_value': withdraw_l22['txid'], 'new_value': NEW_VALUES_LIST['withdraw_txid_l22']},
            {'data_keys': ['psbt'], 'original_value': withdraw_l22['psbt'], 'new_value': NEW_VALUES_LIST['psbt_8']},
            {'data_keys': ['created_at'], 'original_value': getlog_res1['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['bytes_used'], 'original_value': getlog_res1['bytes_used'], 'new_value': NEW_VALUES_LIST['bytes_used']},
            {'data_keys': ['bytes_max'], 'original_value': getlog_res1['bytes_max'], 'new_value': NEW_VALUES_LIST['bytes_max']},
            {'data_keys': ['log'], 'original_value': getlog_res1['log'], 'new_value': example_log},
        ])
        logger.info('General Utils Done!')
        return address_l22
    except Exception as e:
        logger.error(f'Error in generating utils examples: {e}')
        raise


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
        spsigned_res1 = update_example(node=l7, method='splice_signed', params={'channel_id': chan_id_78, 'psbt': signpsbt_res1['signed_psbt']})

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
        spsigned_res2 = update_example(node=l7, method='splice_signed', params={'channel_id': chan_id_78, 'psbt': spupdate2_res2['psbt']})
        update_example(node=l7, method='stop', params={})

        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['any', 'channel_id', 'account'], 'original_value': chan_id_78, 'new_value': NEW_VALUES_LIST['c78_channel_id']},
            {'data_keys': ['any', 'psbt'], 'original_value': spinit_res1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_1']},
            {'data_keys': ['any', 'psbt'], 'original_value': spinit_res2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_2']},
            {'data_keys': ['any', 'initialpsbt', 'psbt'], 'original_value': funds_result_1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_3']},
            {'data_keys': ['any', 'initialpsbt', 'psbt'], 'original_value': funds_result_2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_4']},
            {'data_keys': ['psbt'], 'original_value': spupdate2_res1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_5_2']},
            {'data_keys': ['tx'], 'original_value': spsigned_res1['tx'], 'new_value': NEW_VALUES_LIST['send_tx_1']},
            {'data_keys': ['txid'], 'original_value': spsigned_res1['txid'], 'new_value': NEW_VALUES_LIST['send_txid_1']},
            {'data_keys': ['psbt'], 'original_value': spsigned_res1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_1']},
            {'data_keys': ['tx'], 'original_value': spsigned_res2['tx'], 'new_value': NEW_VALUES_LIST['send_tx_2']},
            {'data_keys': ['txid'], 'original_value': spsigned_res2['txid'], 'new_value': NEW_VALUES_LIST['send_txid_2']},
            {'data_keys': ['psbt'], 'original_value': spsigned_res2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_2']},
            {'data_keys': ['psbt'], 'original_value': signpsbt_res1['signed_psbt'], 'new_value': NEW_VALUES_LIST['signed_psbt_1']},
            {'data_keys': ['psbt'], 'original_value': spupdate1_res1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_1']},
            {'data_keys': ['any', 'psbt'], 'original_value': spupdate1_res2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_2']},
        ])
        logger.info('Splice Done!')
    except Exception as e:
        logger.error(f'Error in generating splicing examples: {e}')
        raise


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

        fund_start_res1 = update_example(node=l9, method='fundchannel_start', params=[l10.info['id'], amount])
        outputs_1 = [{fund_start_res1['funding_address']: amount}]
        example_outputs_1 = [{'bcrt1p00' + ('02' * 28): amount}]
        tx_prep_1 = update_example(node=l9, method='txprepare', params=[outputs_1])
        update_example(node=l9, method='fundchannel_cancel', params=[l10.info['id']])
        txdiscard_res1 = update_example(node=l9, method='txdiscard', params=[tx_prep_1['txid']])
        fund_start_res2 = update_example(node=l9, method='fundchannel_start', params={'id': l10.info['id'], 'amount': amount})
        outputs_2 = [{fund_start_res2['funding_address']: amount}]
        example_outputs_2 = [{'bcrt1p00' + ('03' * 28): amount}]
        tx_prep_2 = update_example(node=l9, method='txprepare', params={'outputs': outputs_2})
        fcc_res1 = update_example(node=l9, method='fundchannel_complete', params=[l10.info['id'], tx_prep_2['psbt']])
        txsend_res1 = update_example(node=l9, method='txsend', params=[tx_prep_2['txid']])
        l9.rpc.close(l10.info['id'])

        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l9])

        amount = 1000000
        fund_start_res3 = l9.rpc.fundchannel_start(l10.info['id'], amount)
        tx_prep_3 = l9.rpc.txprepare([{fund_start_res3['funding_address']: amount}])
        update_example(node=l9, method='fundchannel_cancel', params={'id': l10.info['id']})
        txdiscard_res2 = update_example(node=l9, method='txdiscard', params={'txid': tx_prep_3['txid']})
        funding_addr = l9.rpc.fundchannel_start(l10.info['id'], amount)['funding_address']
        tx_prep_4 = l9.rpc.txprepare([{funding_addr: amount}])
        fcc_res2 = update_example(node=l9, method='fundchannel_complete', params={'id': l10.info['id'], 'psbt': tx_prep_4['psbt']})
        txsend_res2 = update_example(node=l9, method='txsend', params={'txid': tx_prep_4['txid']})
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
        c1112res = l11.rpc.fundchannel(l12.info['id'], FUND_CHANNEL_AMOUNT_SAT)
        chan_id = c1112res['channel_id']
        vins = bitcoind.rpc.decoderawtransaction(c1112res['tx'])['vin']
        assert(only_one(vins))
        prev_utxos = ["{}:{}".format(vins[0]['txid'], vins[0]['vout'])]
        example_utxos = ['utxo' + ('01' * 30) + ':1']

        l11.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')
        chan = only_one(l11.rpc.listpeerchannels(l12.info['id'])['channels'])
        rate = int(chan['feerate']['perkw'])
        next_feerate = '{}perkw'.format(rate * 4)

        # Initiate an RBF
        startweight = 42 + 172
        initpsbt_1 = update_example(node=l11, method='utxopsbt', params=[FUND_CHANNEL_AMOUNT_SAT, next_feerate, startweight, prev_utxos, None, True, None, None, True])
        openchannelbump_res1 = update_example(node=l11, method='openchannel_bump', params=[chan_id, FUND_CHANNEL_AMOUNT_SAT, initpsbt_1['psbt'], next_feerate])

        update_example(node=l11, method='openchannel_abort', params={'channel_id': chan_id})
        openchannelbump_res2 = update_example(node=l11, method='openchannel_bump', params={'channel_id': chan_id, 'amount': FUND_CHANNEL_AMOUNT_SAT, 'initialpsbt': initpsbt_1['psbt'], 'funding_feerate': next_feerate})
        openchannelupdate_res1 = update_example(node=l11, method='openchannel_update', params={'channel_id': chan_id, 'psbt': openchannelbump_res2['psbt']})
        signed_psbt_1 = update_example(node=l11, method='signpsbt', params={'psbt': openchannelupdate_res1['psbt']})
        openchannelsigned_res1 = update_example(node=l11, method='openchannel_signed', params={'channel_id': chan_id, 'signed_psbt': signed_psbt_1['signed_psbt']})

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
        openchannelsigned_res2 = update_example(node=l11, method='openchannel_signed', params=[chan_id, signed_psbt_2['signed_psbt']])

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
        outputs = l4.rpc.listfunds()['outputs']
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
        example_destinations_1 = [
            {
                'id': 'nodeid' + ('03' * 30) + '@127.0.0.1:19736',
                'amount': '20000sat'
            },
            {
                'id': 'nodeid' + ('04' * 30) + '@127.0.0.1:19737',
                'amount': '0.0003btc'
            },
            {
                'id': 'nodeid' + ('05' * 30) + '@127.0.0.1:19738',
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
        example_destinations_2 = [
            {
                'id': f'fakenodeid' + ('03' * 28) + '@127.0.0.1:19736',
                'amount': 50000
            },
            {
                'id': 'nodeid' + ('04' * 30) + '@127.0.0.1:19737',
                'amount': 50000
            },
            {
                'id': 'nodeid' + ('01' * 30) + '@127.0.0.1:19734',
                'amount': 50000
            }
        ]
        multifund_res2 = update_example(node=l1, method='multifundchannel', params={'destinations': destinations_2, 'minchannels': 1})
        # Close newly funded channels to bring the setup back to initial state
        for channel in multifund_res2['channel_ids']:
            l1.rpc.close(channel['channel_id'])
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['any', 'id', 'pubkey', 'destination'], 'original_value': l10.info['id'], 'new_value': NEW_VALUES_LIST['l10_id']},
            {'data_keys': ['any', 'id', 'pubkey', 'destination'], 'original_value': l12.info['id'], 'new_value': NEW_VALUES_LIST['l12_id']},
            {'data_keys': ['any', 'txid'], 'original_value': tx_prep_1['txid'], 'new_value': NEW_VALUES_LIST['txprep_txid_1']},
            {'data_keys': ['initialpsbt', 'psbt', 'signed_psbt'], 'original_value': tx_prep_1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_9']},
            {'data_keys': ['unsigned_tx'], 'original_value': tx_prep_2['unsigned_tx'], 'new_value': NEW_VALUES_LIST['unsigned_tx_1']},
            {'data_keys': ['any', 'initialpsbt', 'psbt', 'signed_psbt'], 'original_value': tx_prep_2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_10']},
            {'data_keys': ['any', 'txid'], 'original_value': tx_prep_2['txid'], 'new_value': NEW_VALUES_LIST['txprep_txid_2']},
            {'data_keys': ['any', 'txid'], 'original_value': tx_prep_3['txid'], 'new_value': NEW_VALUES_LIST['txprep_txid_3']},
            {'data_keys': ['txid'], 'original_value': tx_prep_4['txid'], 'new_value': NEW_VALUES_LIST['txprep_txid_4']},
            {'data_keys': ['initialpsbt', 'psbt', 'signed_psbt'], 'original_value': tx_prep_4['psbt'], 'new_value': NEW_VALUES_LIST['psbt_12']},
            {'data_keys': ['channel_id', 'account'], 'original_value': fcc_res1['channel_id'], 'new_value': NEW_VALUES_LIST['c910_channel_id_1']},
            {'data_keys': ['channel_id', 'account'], 'original_value': fcc_res2['channel_id'], 'new_value': NEW_VALUES_LIST['c910_channel_id_2']},
            {'data_keys': ['txid'], 'original_value': c1112res['txid'], 'new_value': NEW_VALUES_LIST['c1112_txid']},
            {'data_keys': ['channel_id', 'account'], 'original_value': c1112res['channel_id'], 'new_value': NEW_VALUES_LIST['c1112_channel_id']},
            {'data_keys': ['tx'], 'original_value': c35res['tx'], 'new_value': NEW_VALUES_LIST['c35_tx']},
            {'data_keys': ['txid'], 'original_value': c35res['txid'], 'new_value': NEW_VALUES_LIST['c35_txid']},
            {'data_keys': ['channel_id', 'account'], 'original_value': c35res['channel_id'], 'new_value': NEW_VALUES_LIST['c35_channel_id']},
            {'data_keys': ['tx'], 'original_value': c41res['tx'], 'new_value': NEW_VALUES_LIST['c41_tx']},
            {'data_keys': ['txid', 'funding_txid'], 'original_value': c41res['txid'], 'new_value': NEW_VALUES_LIST['c41_txid']},
            {'data_keys': ['channel_id', 'account'], 'original_value': c41res['channel_id'], 'new_value': NEW_VALUES_LIST['c41_channel_id']},
            {'data_keys': ['destinations'], 'original_value': destinations_1, 'new_value': example_destinations_1},
            {'data_keys': ['channel_id', 'account'], 'original_value': multifund_res1['channel_ids'][0]['channel_id'], 'new_value': NEW_VALUES_LIST['mf_channel_id_1']},
            {'data_keys': ['channel_id', 'account'], 'original_value': multifund_res1['channel_ids'][1]['channel_id'], 'new_value': NEW_VALUES_LIST['mf_channel_id_2']},
            {'data_keys': ['channel_id', 'account'], 'original_value': multifund_res1['channel_ids'][2]['channel_id'], 'new_value': NEW_VALUES_LIST['mf_channel_id_3']},
            {'data_keys': ['tx'], 'original_value': multifund_res1['tx'], 'new_value': NEW_VALUES_LIST['multi_tx_1']},
            {'data_keys': ['txid', 'funding_txid'], 'original_value': multifund_res1['txid'], 'new_value': NEW_VALUES_LIST['multi_txid_1']},
            {'data_keys': ['destinations'], 'original_value': destinations_2, 'new_value': example_destinations_2},
            {'data_keys': ['channel_id', 'account'], 'original_value': multifund_res2['channel_ids'][0]['channel_id'], 'new_value': NEW_VALUES_LIST['mf_channel_id_4']},
            {'data_keys': ['tx'], 'original_value': multifund_res2['tx'], 'new_value': NEW_VALUES_LIST['multi_tx_2']},
            {'data_keys': ['txid'], 'original_value': multifund_res2['txid'], 'new_value': NEW_VALUES_LIST['multi_txid_2']},
            {'data_keys': ['message'], 'original_value': multifund_res2['failed'][0]['error']['message'], 'new_value': NEW_VALUES_LIST['error_message_1']},
            {'data_keys': ['utxos'], 'original_value': [utxo], 'new_value': [NEW_VALUES_LIST['c35_txid'] + ':1']},
            {'data_keys': ['any', 'funding_address'], 'original_value': fund_start_res1['funding_address'], 'new_value': NEW_VALUES_LIST['destination_4']},
            {'data_keys': ['any', 'outputs'], 'original_value': outputs_1, 'new_value': example_outputs_1},
            {'data_keys': ['scriptpubkey'], 'original_value': fund_start_res1['scriptpubkey'], 'new_value': NEW_VALUES_LIST['script_pubkey_1']},
            {'data_keys': ['any', 'funding_address'], 'original_value': fund_start_res2['funding_address'], 'new_value': NEW_VALUES_LIST['destination_5']},
            {'data_keys': ['any', 'outputs'], 'original_value': outputs_2, 'new_value': example_outputs_2},
            {'data_keys': ['scriptpubkey'], 'original_value': fund_start_res2['scriptpubkey'], 'new_value': NEW_VALUES_LIST['script_pubkey_2']},
            {'data_keys': ['initialpsbt', 'psbt'], 'original_value': psbt_init_res1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_13']},
            {'data_keys': ['any', 'initialpsbt', 'psbt'], 'original_value': psbt_init_res2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_14']},
            {'data_keys': ['any', 'txid'], 'original_value': initpsbt_1['reservations'][0]['txid'], 'new_value': NEW_VALUES_LIST['utxo_1']},
            {'data_keys': ['any', 'initialpsbt', 'psbt'], 'original_value': initpsbt_1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_15']},
            {'data_keys': ['any', 'initialpsbt', 'psbt'], 'original_value': initpsbt_2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_16']},
            {'data_keys': ['any', 'txid'], 'original_value': initpsbt_2['reservations'][0]['txid'], 'new_value': NEW_VALUES_LIST['utxo_1']},
            {'data_keys': ['initialpsbt', 'psbt', 'signed_psbt'], 'original_value': openchannelinit_res1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_17']},
            {'data_keys': ['funding_serial'], 'original_value': openchannelinit_res1['funding_serial'], 'new_value': NEW_VALUES_LIST['funding_serial_1']},
            {'data_keys': ['initialpsbt', 'psbt', 'signed_psbt'], 'original_value': openchannelinit_res2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_18']},
            {'data_keys': ['funding_serial'], 'original_value': openchannelinit_res2['funding_serial'], 'new_value': NEW_VALUES_LIST['funding_serial_2']},
            {'data_keys': ['initialpsbt', 'psbt', 'signed_psbt'], 'original_value': openchannelbump_res1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_19']},
            {'data_keys': ['initialpsbt', 'psbt', 'signed_psbt'], 'original_value': openchannelbump_res2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_20']},
            {'data_keys': ['any', 'initialpsbt', 'psbt', 'signed_psbt'], 'original_value': openchannelbump_res3['psbt'], 'new_value': NEW_VALUES_LIST['psbt_21']},
            {'data_keys': ['funding_serial'], 'original_value': openchannelbump_res1['funding_serial'], 'new_value': NEW_VALUES_LIST['funding_serial_3']},
            {'data_keys': ['funding_serial'], 'original_value': openchannelbump_res2['funding_serial'], 'new_value': NEW_VALUES_LIST['funding_serial_4']},
            {'data_keys': ['funding_serial'], 'original_value': openchannelbump_res3['funding_serial'], 'new_value': NEW_VALUES_LIST['funding_serial_5']},
            {'data_keys': ['signed_psbt'], 'original_value': signed_psbt_1['signed_psbt'], 'new_value': NEW_VALUES_LIST['psbt_22']},
            {'data_keys': ['tx'], 'original_value': openchannelsigned_res1['tx'], 'new_value': NEW_VALUES_LIST['ocs_tx_1']},
            {'data_keys': ['txid'], 'original_value': openchannelsigned_res1['txid'], 'new_value': NEW_VALUES_LIST['ocs_txid_1']},
            {'data_keys': ['any', 'signed_psbt'], 'original_value': signed_psbt_2['signed_psbt'], 'new_value': NEW_VALUES_LIST['psbt_23']},
            {'data_keys': ['tx'], 'original_value': openchannelsigned_res2['tx'], 'new_value': NEW_VALUES_LIST['ocs_tx_2']},
            {'data_keys': ['txid'], 'original_value': openchannelsigned_res2['txid'], 'new_value': NEW_VALUES_LIST['ocs_txid_2']},
            {'data_keys': ['psbt'], 'original_value': psbt_1, 'new_value': NEW_VALUES_LIST['psbt_24']},
            {'data_keys': ['psbt'], 'original_value': psbt_2, 'new_value': NEW_VALUES_LIST['psbt_25']},
            {'data_keys': ['any'], 'original_value': prev_utxos, 'new_value': example_utxos},
            {'data_keys': ['unsigned_tx'], 'original_value': txdiscard_res1['unsigned_tx'], 'new_value': NEW_VALUES_LIST['unsigned_tx_3']},
            {'data_keys': ['unsigned_tx'], 'original_value': txdiscard_res2['unsigned_tx'], 'new_value': NEW_VALUES_LIST['unsigned_tx_4']},
            {'data_keys': ['tx'], 'original_value': txsend_res1['tx'], 'new_value': NEW_VALUES_LIST['txsend_tx_1']},
            {'data_keys': ['psbt'], 'original_value': txsend_res1['psbt'], 'new_value': NEW_VALUES_LIST['psbt_24']},
            {'data_keys': ['tx'], 'original_value': txsend_res2['tx'], 'new_value': NEW_VALUES_LIST['txsend_tx_2']},
            {'data_keys': ['psbt'], 'original_value': txsend_res2['psbt'], 'new_value': NEW_VALUES_LIST['psbt_26']},
        ])
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
        global FUND_CHANNEL_AMOUNT_SAT
        l2.rpc.close(l5.info['id'])
        dfc_res1 = update_example(node=l2, method='dev-forget-channel', params={'id': l5.info['id']}, description=[f'Forget a channel by peer pubkey when only one channel exists with the peer:'])

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
        delinv_res1 = update_example(node=l3, method='delinvoice', params={'label': 'lbl_l36', 'status': 'unpaid'})

        # invoice already deleted, pay will fail; used for delpay failed example
        with pytest.raises(RpcError):
            l1.rpc.pay(inv_l36['bolt11'])

        listsendpays_l1 = l1.rpc.listsendpays()['payments']
        sendpay_g1_p1 = next((x for x in listsendpays_l1 if 'groupid' in x and x['groupid'] == 1 and 'partid' in x and x['partid'] == 2), None)
        delpay_res1 = update_example(node=l1, method='delpay', params={'payment_hash': listsendpays_l1[0]['payment_hash'], 'status': 'complete'})
        delpay_res2 = update_example(node=l1, method='delpay', params=[listsendpays_l1[-1]['payment_hash'], listsendpays_l1[-1]['status']])
        delpay_res3 = update_example(node=l1, method='delpay', params={'payment_hash': sendpay_g1_p1['payment_hash'], 'status': sendpay_g1_p1['status'], 'groupid': 1, 'partid': 2})
        delinv_res2 = update_example(node=l3, method='delinvoice', params={'label': 'lbl_l37', 'status': 'paid', 'desconly': True})

        # Delforward
        failed_forwards = l2.rpc.listforwards('failed')['forwards']
        local_failed_forwards = l2.rpc.listforwards('local_failed')['forwards']
        if len(local_failed_forwards) > 0 and 'in_htlc_id' in local_failed_forwards[0]:
            update_example(node=l2, method='delforward', params={'in_channel': c12, 'in_htlc_id': local_failed_forwards[0]['in_htlc_id'], 'status': 'local_failed'})
        if len(failed_forwards) > 0 and 'in_htlc_id' in failed_forwards[0]:
            update_example(node=l2, method='delforward', params={'in_channel': c12, 'in_htlc_id': failed_forwards[0]['in_htlc_id'], 'status': 'failed'})
        dfc_res2 = update_example(node=l2, method='dev-forget-channel', params={'id': l3.info['id'], 'short_channel_id': c23, 'force': True}, description=[f'Forget a channel by short channel id when peer has multiple channels:'])

        # Autoclean
        update_example(node=l2, method='autoclean-once', params=['failedpays', 1])
        update_example(node=l2, method='autoclean-once', params=['succeededpays', 1])
        update_example(node=l2, method='autoclean-status', params={'subsystem': 'expiredinvoices'})
        update_example(node=l2, method='autoclean-status', params={})
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['any', 'bolt11'], 'original_value': delinv_res1['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_di_1']},
            {'data_keys': ['payment_hash'], 'original_value': delinv_res1['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_di_1']},
            {'data_keys': ['expires_at'], 'original_value': delinv_res1['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['any', 'bolt11'], 'original_value': delinv_res2['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_di_2']},
            {'data_keys': ['payment_hash'], 'original_value': delinv_res2['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_di_2']},
            {'data_keys': ['paid_at'], 'original_value': delinv_res2['paid_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['expires_at'], 'original_value': delinv_res2['expires_at'], 'new_value': NEW_VALUES_LIST['time_at_900']},
            {'data_keys': ['payment_preimage'], 'original_value': delinv_res2['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_di_1']},
            {'data_keys': ['payment_hash'], 'original_value': delpay_res1['payments'][0]['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_dp_1']},
            {'data_keys': ['payment_preimage'], 'original_value': delpay_res1['payments'][0]['payment_preimage'], 'new_value': NEW_VALUES_LIST['payment_preimage_dp_1']},
            {'data_keys': ['any', 'bolt11'], 'original_value': delpay_res1['payments'][0]['bolt11'], 'new_value': NEW_VALUES_LIST['bolt11_dp_1']},
            {'data_keys': ['created_at'], 'original_value': delpay_res1['payments'][0]['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['completed_at'], 'original_value': delpay_res1['payments'][0]['completed_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['any', 'payment_hash'], 'original_value': delpay_res2['payments'][0]['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_dp_2']},
            {'data_keys': ['created_at'], 'original_value': delpay_res2['payments'][0]['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['completed_at'], 'original_value': delpay_res2['payments'][0]['completed_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['payment_hash'], 'original_value': delpay_res3['payments'][0]['payment_hash'], 'new_value': NEW_VALUES_LIST['payment_hash_dp_3']},
            {'data_keys': ['created_at'], 'original_value': delpay_res3['payments'][0]['created_at'], 'new_value': NEW_VALUES_LIST['time_at_800']},
            {'data_keys': ['completed_at'], 'original_value': delpay_res3['payments'][0]['completed_at'], 'new_value': NEW_VALUES_LIST['time_at_850']},
            {'data_keys': ['funding_txid'], 'original_value': dfc_res1['funding_txid'], 'new_value': NEW_VALUES_LIST['funding_txid_1']},
            {'data_keys': ['funding_txid'], 'original_value': dfc_res2['funding_txid'], 'new_value': NEW_VALUES_LIST['funding_txid_2']},
        ])
        logger.info('Auto-clean and Delete Done!')
    except Exception as e:
        logger.error(f'Error in generating autoclean and delete examples: {e}')
        raise


def generate_backup_recovery_examples(node_factory, l4, l5, l6):
    """Node backup and recovery examples"""
    try:
        logger.info('Backup and Recovery Start...')

        # New node l13 used for recover and exposesecret examples
        l13 = node_factory.get_node(options={'exposesecret-passphrase': "test_exposesecret"})
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
        example_scb = [
            '0000000000000001' + NEW_VALUES_LIST['c34_channel_id'] + NEW_VALUES_LIST['l3_id'] + '00017f000001' + ('0340' * 23) + '0003401000',
            '0000000000000002' + NEW_VALUES_LIST['c34_2_channel_id'] + NEW_VALUES_LIST['l3_id'] + '00017f000001' + ('0342' * 23) + '0003401000',
            '0000000000000003' + NEW_VALUES_LIST['c41_channel_id'] + NEW_VALUES_LIST['l1_id'] + '00017f000001' + ('0410' * 23) + '0003401000',
            '0000000000000004' + NEW_VALUES_LIST['c12_channel_id'] + NEW_VALUES_LIST['l1_id'] + '00017f000001' + ('0120' * 23) + '0003401000',
            '0000000000000005' + NEW_VALUES_LIST['mf_channel_id_4'] + NEW_VALUES_LIST['l1_id'] + '00017f000001' + ('0152' * 23) + '0003401000',
            '0000000000000006' + NEW_VALUES_LIST['mf_channel_id_5'] + NEW_VALUES_LIST['l2_id'] + '00017f000001' + ('0124' * 23) + '0003401000',
        ]
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
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['hsmsecret'], 'original_value': l13codex32, 'new_value': NEW_VALUES_LIST['hsm_secret_cdx_1']},
            {'data_keys': ['scb'], 'original_value': backup_l4['scb'], 'new_value': example_scb},
            {'data_keys': ['channel_id', 'account'], 'original_value': backup_l4['scb'][5][16:(16 + 64)], 'new_value': NEW_VALUES_LIST['mf_channel_id_5']},
        ])
        logger.info('Backup and Recovery Done!')
    except Exception as e:
        logger.error(f'Error in generating backup and recovery examples: {e}')
        raise


def generate_list_examples(l1, l2, l3, c12, c23_2, inv_l31, inv_l32, offer_l23, inv_req_l1_l22, address_l22):
    """Generates lists rpc examples"""
    try:
        logger.info('Lists Start...')
        # Transactions Lists
        FUNDS_LEN = 3
        listfunds_res1 = l1.rpc.listfunds()
        listfunds_res1 = update_list_responses(listfunds_res1, list_key='outputs', slice_upto=FUNDS_LEN)
        listfunds_res1['channels'] = [channel for channel in listfunds_res1['channels'] if channel['peer_id'] != '0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199']
        listfunds_res1['channels'] = sorted(listfunds_res1['channels'], key=lambda x: x['peer_id'])
        for i in range(1, FUNDS_LEN + 1):
            lfoutput = listfunds_res1['outputs'][i - 1]
            lfchannel = listfunds_res1['channels'][i - 1]
            lfoutput['output'] = i + 1
            lfoutput['txid'] = 'txid' + (('0000' + str(i)) * 12)
            lfoutput['scriptpubkey'] = 'scriptpubkey' + (f"{i:02}" * 28)
            lfoutput['address'] = 'bcrt1p00' + ('04' * 28)
            lfoutput['blockheight'] = NEW_VALUES_LIST['blockheight_160']
            lfoutput['amount_msat'] = 25000000 + (i * 1000000)
            lfchannel['funding_output'] = i
            lfchannel['funding_txid'] = 'txid' + (('0100' + str(i)) * 12)
            lfchannel['amount_msat'] = 10000000 + (i * 1000000)
            lfchannel['our_amount_msat'] = 35000000 + (i * 1000000)
        update_example(node=l1, method='listfunds', params={}, response=listfunds_res1)

        listforwards_res1 = l2.rpc.listforwards(in_channel=c12, out_channel=c23_2, status='settled')
        listforwards_res1 = update_list_responses(listforwards_res1, list_key='forwards', slice_upto=5, update_func=lambda x, i: x.update({'received_time': NEW_VALUES_LIST['time_at_800'] + (i * 10000), 'resolved_time': NEW_VALUES_LIST['time_at_850'] + (i * 10000)}))
        update_example(node=l2, method='listforwards', params={'in_channel': c12, 'out_channel': c23_2, 'status': 'settled'}, response=listforwards_res1)
        listforwards_res2 = l2.rpc.listforwards()
        listforwards_res2 = update_list_responses(listforwards_res2, list_key='forwards', slice_upto=5, update_func=lambda x, i: x.update({'received_time': NEW_VALUES_LIST['time_at_800'] + (i * 10000), 'resolved_time': NEW_VALUES_LIST['time_at_850'] + (i * 10000)}))
        update_example(node=l2, method='listforwards', params={}, response=listforwards_res2)

        listinvoices_res1 = l2.rpc.listinvoices(label='lbl_l21')
        listinvoices_res1 = update_list_responses(listinvoices_res1, list_key='invoices', slice_upto=5, update_func=lambda x, i: x.update({'paid_at': NEW_VALUES_LIST['time_at_850'] + (i * 10000), 'expires_at': NEW_VALUES_LIST['time_at_900'] + (i * 10000)}))
        update_example(node=l2, method='listinvoices', params={'label': 'lbl_l21'}, response=listinvoices_res1)
        listinvoices_res2 = l2.rpc.listinvoices()
        listinvoices_res2 = update_list_responses(listinvoices_res2, list_key='invoices', slice_upto=5, update_func=lambda x, i: x.update({'paid_at': NEW_VALUES_LIST['time_at_850'] + (i * 10000), 'expires_at': NEW_VALUES_LIST['time_at_900'] + (i * 10000)}))
        update_example(node=l2, method='listinvoices', params={}, response=listinvoices_res2)

        listhtlcs_res1 = l1.rpc.listhtlcs(c12)
        listhtlcs_res1 = update_list_responses(listhtlcs_res1, list_key='htlcs')
        update_example(node=l1, method='listhtlcs', params=[c12], response=listhtlcs_res1)
        listhtlcs_res2 = l1.rpc.listhtlcs()
        listhtlcs_res2 = update_list_responses(listhtlcs_res2, list_key='htlcs')
        update_example(node=l1, method='listhtlcs', params={}, response=listhtlcs_res2)

        listsendpays_res1 = l1.rpc.listsendpays(bolt11=inv_l31['bolt11'])
        listsendpays_res1 = update_list_responses(listsendpays_res1, list_key='payments', slice_upto=5, update_func=lambda x, i: x.update({'created_at': NEW_VALUES_LIST['time_at_800'] + (i * 10000), 'completed_at': NEW_VALUES_LIST['time_at_900'] + (i * 10000)}))
        update_example(node=l1, method='listsendpays', params={'bolt11': inv_l31['bolt11']}, response=listsendpays_res1)
        listsendpays_res2 = l1.rpc.listsendpays()
        listsendpays_res2 = update_list_responses(listsendpays_res2, list_key='payments', slice_upto=5, update_func=lambda x, i: x.update({'created_at': NEW_VALUES_LIST['time_at_800'] + (i * 10000), 'completed_at': NEW_VALUES_LIST['time_at_900'] + (i * 10000)}))
        update_example(node=l1, method='listsendpays', params={}, response=listsendpays_res2)

        listpays_res1 = l2.rpc.listpays(bolt11=inv_l32['bolt11'])
        listpays_res1 = update_list_responses(listpays_res1, list_key='pays')
        update_example(node=l2, method='listpays', params={'bolt11': inv_l32['bolt11']}, response=listpays_res1)
        listpays_res2 = l2.rpc.listpays()
        listpays_res2 = update_list_responses(listpays_res2, list_key='pays')
        update_example(node=l2, method='listpays', params={}, response=listpays_res2)

        listtransactions_res1 = l1.rpc.listtransactions()
        listtransactions_res1 = update_list_responses(listtransactions_res1, list_key='transactions', slice_upto=2)
        for i, transaction in enumerate(listtransactions_res1['transactions'], start=1):
            transaction['hash'] = 'txid' + (('7000' + str(i)) * 11)
            transaction['rawtx'] = '02000000000101lstx' + (('7000' + str(i)) * 34)
            transaction['locktime'] = 549000000 + (i * 100)
            transaction['inputs'] = transaction['inputs'][0:1]
            transaction['inputs'][0]['txid'] = 'txid' + (('6001' + str(i)) * 12)
            transaction['inputs'][0]['index'] = 1
            transaction['inputs'][0]['sequence'] = 2158510000 + (i * 1000)
            for k, output in enumerate(transaction['outputs'], start=1):
                output['scriptPubKey'] = 'scriptpubkey' + ((f"{i:02}" + f"{k:02}") * 14)
                output['index'] = k
                output['amount_msat'] = 201998900000 + (i * 1000) + (k * 100)
        update_example(node=l1, method='listtransactions', params={}, response=listtransactions_res1)
        listclosedchannels_res1 = l2.rpc.listclosedchannels()
        listclosedchannels_res1 = update_list_responses(listclosedchannels_res1, list_key='closedchannels')
        for i, closedchannel in enumerate(listclosedchannels_res1['closedchannels'], start=1):
            closedchannel['last_commitment_fee_msat'] = 2894000 + (i * 1000)
            closedchannel['last_commitment_txid'] = 'txidcloselastcommitment0' + (('0000' + str(i)) * 8)
            closedchannel['last_stable_connection'] = NEW_VALUES_LIST['time_at_850']
            closedchannel['alias'] = {'local': '12' + str(i) + 'x13' + str(i) + 'x14' + str(i), 'remote': '15' + str(i) + 'x16' + str(i) + 'x17' + str(i)}
        update_example(node=l2, method='listclosedchannels', params={}, response=listclosedchannels_res1)

        update_example(node=l2, method='listconfigs', params={'config': 'network'})
        update_example(node=l2, method='listconfigs', params={'config': 'experimental-dual-fund'})
        l2.rpc.jsonschemas = {}
        listconfigs_res3 = l2.rpc.listconfigs()
        listconfigs_res3['configs']['htlc-maximum-msat']['value_msat'] = NEW_VALUES_LIST['htlc_max_msat']
        listconfigs_res3 = update_list_responses(listconfigs_res3, list_key='configs', slice_upto=len(listconfigs_res3['configs']), update_func=None, sort=True)
        update_example(node=l2, method='listconfigs', params={}, response=listconfigs_res3)

        update_example(node=l2, method='listsqlschemas', params={'table': 'offers'})
        update_example(node=l2, method='listsqlschemas', params=['closedchannels'])

        listpeerchannels_res1 = l1.rpc.listpeerchannels(l2.info['id'])
        listpeerchannels_res1 = update_list_responses(listpeerchannels_res1, list_key='channels', slice_upto=3)
        for i, channel in enumerate(listpeerchannels_res1['channels'], start=1):
            channel['last_stable_connection'] = NEW_VALUES_LIST['time_at_850'] + (i * 10000)
            channel['scratch_txid'] = 'scratchid1' + (('0' + str(i)) * 27)
            channel['alias']['local'] = '3000000' + str(i) + 'x6000000' + str(i) + 'x6000' + str(i)
            channel['alias']['remote'] = '1000000' + str(i) + 'x2000000' + str(i) + 'x3000' + str(i)
            channel['max_total_htlc_in_msat'] = NEW_VALUES_LIST['htlc_max_msat']
            for j, state in enumerate(channel['state_changes'], start=1):
                state['timestamp'] = '2024-10-10T00:0' + str(j) + ':00.000Z'
        update_example(node=l1, method='listpeerchannels', params={'id': l2.info['id']}, response=listpeerchannels_res1)
        listpeerchannels_res2 = l1.rpc.listpeerchannels()
        listpeerchannels_2 = None
        listpeerchannels_3 = None
        i = 0
        for channel in listpeerchannels_res2['channels']:
            if channel['peer_id'] == l2.info['id'] or channel['peer_id'] == l3.info['id']:
                i = 2 if channel['peer_id'] == l2.info['id'] else 3
                scrt_id = 'scratchid2' + (('0' + str(i)) * 27)
                channel['last_stable_connection'] = NEW_VALUES_LIST['time_at_850'] + (i * 10000)
                channel['scratch_txid'] = scrt_id
                channel['alias']['local'] = '3000000' + str(i) + 'x6000000' + str(i) + 'x6000' + str(i)
                channel['alias']['remote'] = '1000000' + str(i) + 'x2000000' + str(i) + 'x3000' + str(i)
                channel['close_to_addr'] = 'bcrt1pcl' + (('000' + str(i)) * 14)
                channel['close_to'] = 'db2dec31' + (('0' + str(i)) * 30)
                channel['status'][0] = re.sub(r'(tx:)[a-f0-9]+', r'\1' + scrt_id, channel['status'][0])
                channel['max_total_htlc_in_msat'] = NEW_VALUES_LIST['htlc_max_msat']
                if 'inflight' in channel and len(channel['inflight']) > 0:
                    channel['inflight'][0]['scratch_txid'] = scrt_id
                for j, state in enumerate(channel['state_changes'], start=1):
                    state['timestamp'] = '2024-10-10T00:0' + str(j) + ':00.000Z'
                if channel['peer_id'] == l2.info['id']:
                    listpeerchannels_2 = channel
                else:
                    listpeerchannels_3 = channel
        listpeerchannels_res2['channels'] = [channel for channel in [listpeerchannels_2, listpeerchannels_3] if channel is not None]
        update_example(node=l1, method='listpeerchannels', params={}, response=listpeerchannels_res2)

        listchannels_res1 = l1.rpc.listchannels(c12)
        listchannels_res1 = update_list_responses(listchannels_res1, list_key='channels', slice_upto=5, update_func=lambda x, i: x.update({'last_update': NEW_VALUES_LIST['time_at_850'] + (i * 10000), 'channel_flags': i, 'active': i % 2 == 0}))
        update_example(node=l1, method='listchannels', params={'short_channel_id': c12}, response=listchannels_res1)
        listchannels_res2 = l1.rpc.listchannels()
        listchannels_res2 = update_list_responses(listchannels_res2, list_key='channels', slice_upto=5, update_func=lambda x, i: x.update({'last_update': NEW_VALUES_LIST['time_at_850'] + (i * 10000), 'channel_flags': i, 'active': i % 2 == 0}))
        update_example(node=l1, method='listchannels', params={}, response=listchannels_res2)

        listnodes_res1 = l2.rpc.listnodes(l3.info['id'])
        listnodes_res1 = update_list_responses(listnodes_res1, list_key='nodes', slice_upto=5, update_func=lambda x, i: x.update({'last_timestamp': NEW_VALUES_LIST['time_at_800'] + (i * 10000)}))
        update_example(node=l2, method='listnodes', params={'id': l3.info['id']}, response=listnodes_res1)
        listnodes_res2 = l2.rpc.listnodes()
        listnodes_res2 = update_list_responses(listnodes_res2, list_key='nodes', slice_upto=5, update_func=lambda x, i: x.update({'last_timestamp': NEW_VALUES_LIST['time_at_800'] + (i * 10000)}))
        update_example(node=l2, method='listnodes', params={}, response=listnodes_res2)

        listpeers_res1 = l2.rpc.listpeers(l3.info['id'])
        listpeers_res1 = update_list_responses(listpeers_res1, list_key='peers', slice_upto=5, update_func=None, sort=True, sort_key='id')
        update_example(node=l2, method='listpeers', params={'id': l3.info['id']}, response=listpeers_res1)
        listpeers_res2 = l2.rpc.listpeers()
        listpeers_res2 = update_list_responses(listpeers_res2, list_key='peers', slice_upto=5, update_func=None, sort=True, sort_key='id')
        update_example(node=l2, method='listpeers', params={}, response=listpeers_res2)

        update_example(node=l2, method='listdatastore', params={'key': ['employee']})
        update_example(node=l2, method='listdatastore', params={'key': 'somekey'})

        listoffers_res1 = l2.rpc.listoffers(active_only=True)
        listoffers_res1 = update_list_responses(listoffers_res1, list_key='offers')
        update_example(node=l2, method='listoffers', params={'active_only': True}, response=listoffers_res1)
        listoffers_res2 = l2.rpc.listoffers(offer_id=offer_l23['offer_id'])
        listoffers_res2 = update_list_responses(listoffers_res2, list_key='offers')
        update_example(node=l2, method='listoffers', params=[offer_l23['offer_id']], response=listoffers_res2)

        update_example(node=l2, method='listinvoicerequests', params=[inv_req_l1_l22['invreq_id']])
        listinvoicerequests_res2 = l2.rpc.listinvoicerequests()
        listinvoicerequests_res2 = update_list_responses(listinvoicerequests_res2, list_key='invoicerequests', slice_upto=len(listinvoicerequests_res2['invoicerequests']), update_func=None, sort=True, sort_key='used')
        update_example(node=l2, method='listinvoicerequests', params={}, response=listinvoicerequests_res2)
        update_example(node=l2, method='listaddresses', params=[address_l22['p2tr']])
        update_example(node=l2, method='listaddresses', params={'start': 6, 'limit': 2})
        REPLACE_RESPONSE_VALUES.extend([
            {'data_keys': ['any', 'invreq_id'], 'original_value': inv_req_l1_l22['invreq_id'], 'new_value': NEW_VALUES_LIST['invreq_id_l1_l22']},
            {'data_keys': ['netaddr'], 'original_value': listpeers_res2['peers'][0]['netaddr'], 'new_value': [NEW_VALUES_LIST['l1_addr']]},
            {'data_keys': ['any'], 'original_value': listconfigs_res3['configs']['addr']['values_str'][0], 'new_value': NEW_VALUES_LIST['configs_3_addr2']},
            {'data_keys': ['value_int'], 'original_value': listconfigs_res3['configs']['bitcoin-rpcport']['value_int'], 'new_value': NEW_VALUES_LIST['bitcoin-rpcport']},
            {'data_keys': ['value_int'], 'original_value': listconfigs_res3['configs']['grpc-port']['value_int'], 'new_value': NEW_VALUES_LIST['grpc-port']},
            {'data_keys': ['value_str'], 'original_value': listconfigs_res3['configs']['alias']['value_str'], 'new_value': NEW_VALUES_LIST['l2_alias']},
            {'data_keys': ['channel_flags'], 'original_value': listchannels_res2['channels'][-1]['channel_flags'], 'new_value': 2},
        ])
        logger.info('Lists Done!')
    except Exception as e:
        logger.error(f'Error in generating lists examples: {e}')
        raise


@unittest.skipIf(not GENERATE_EXAMPLES, 'Generates examples for doc/schema/lightning-*.json files.')
def test_generate_examples(node_factory, bitcoind, executor):
    """Re-generates examples for doc/schema/lightning-*.json files"""
    try:
        global ALL_RPC_EXAMPLES, REGENERATING_RPCS

        def list_all_examples():
            """list all methods used in 'update_example' calls to ensure that all methods are covered"""
            try:
                global REGENERATING_RPCS
                methods = []
                file_path = os.path.abspath(__file__)

                # Parse and traverse this file's content to list all methods & file names
                with open(file_path, "r") as file:
                    file_content = file.read()
                tree = ast.parse(file_content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'update_example':
                        for keyword in node.keywords:
                            if (keyword.arg == 'method' and isinstance(keyword.value, ast.Str)):
                                if keyword.value.s not in methods:
                                    methods.append(keyword.value.s)
                return methods
            except Exception as e:
                logger.error(f'Error in listing all examples: {e}')
                raise

        def list_missing_examples():
            """Checks for missing example & log an error if missing."""
            try:
                global ALL_RPC_EXAMPLES
                missing_examples = ''
                for file_name in os.listdir('doc/schemas'):
                    if not file_name.endswith('.json'):
                        continue
                    file_name_str = str(file_name).replace('lightning-', '').replace('.json', '')
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
        l1, l2, l3, l4, l5, l6, c12, c23, c25 = setup_test_nodes(node_factory, bitcoind)
        c23_2, c23res2, c34_2, inv_l11, inv_l21, inv_l22, inv_l31, inv_l32, inv_l34 = generate_transactions_examples(l1, l2, l3, l4, l5, c25, bitcoind)
        rune_l21 = generate_runes_examples(l1, l2, l3)
        generate_datastore_examples(l2)
        generate_bookkeeper_examples(l2, l3, c23res2['channel_id'])
        offer_l23, inv_req_l1_l22 = generate_offers_renepay_examples(l1, l2, inv_l21, inv_l34)
        generate_askrene_examples(l1, l2, l3, c12, c23_2)
        generate_wait_examples(l1, l2, bitcoind, executor)
        address_l22 = generate_utils_examples(l1, l2, l3, l4, l5, l6, c23_2, c34_2, inv_l11, inv_l22, rune_l21, bitcoind)
        generate_splice_examples(node_factory, bitcoind)
        generate_channels_examples(node_factory, bitcoind, l1, l3, l4, l5)
        generate_autoclean_delete_examples(l1, l2, l3, l4, l5, c12, c23)
        generate_backup_recovery_examples(node_factory, l4, l5, l6)
        generate_list_examples(l1, l2, l3, c12, c23_2, inv_l31, inv_l32, offer_l23, inv_req_l1_l22, address_l22)
        update_examples_in_schema_files()
        logger.info('All Done!!!')
    except Exception as e:
        logger.error(e)
        sys.exit(1)
