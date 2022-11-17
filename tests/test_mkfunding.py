# Blackbox tests for myfunding devtool
#
# Devtool usage: mkfunding
#   <input-txid> <input-txout> <input-amount>
#   <feerate-per-kw> <input-privkey>
#   <local-funding-privkey> <remote-funding-privkey>
#
# To run tests in this file only, enter this:
#    $ pytest tests/test_mkfunding.py
#

import subprocess
import sys
import traceback

# good command-line values used in test cases
TIMEOUT = 10
EXECUTABLE = 'devtools/mkfunding'
INPUT_TXID = '16835ac8c154b616baac524163f41fb0c4f82c7b972ad35d4d6f18d854f6856b'
INPUT_TXOUTPUT = '1'
INPUT_AMOUNT = '0.01btc'
FEERATE_PER_KW = '253'
INPUT_PRIVKEY = '76edf0c303b9e692da9cb491abedef46ca5b81d32f102eb4648461b239cb0f99'
LOCAL_FUNDING_PRIVKEY = '0000000000000000000000000000000000000000000000000000000000000010'
REMOTE_FUNDING_PRIVKEY = '0000000000000000000000000000000000000000000000000000000000000020'


def subprocess_run(args):
    try:
        response = subprocess.run(
            args,
            timeout=TIMEOUT,
            capture_output=True,
            encoding='utf-8')
        print("*** returncode ***")
        print(response.returncode)
        print("*** stderr ***")
        print(response.stderr)
        print("*** stdout ***")
        print(response.stdout.strip())
        return response
    except Exception:
        # Get current system exception
        ex_type, ex_value, ex_traceback = sys.exc_info()

        # Extract unformatter stack traces as tuples
        trace_back = traceback.extract_tb(ex_traceback)

        # Format stacktrace
        stack_trace = list()

        for trace in trace_back:
            stack_trace.append(
                "File : %s , Line : %d, Func.Name : %s, Message : %s" %
                (trace[0], trace[1], trace[2], trace[3]))

        print("Exception type : %s" % ex_type.__name__)
        print("Exception message : %s" % ex_value)
        print("Stack trace : %s" % stack_trace)


def test_mkfunding_bad_usage():
    response = subprocess_run([EXECUTABLE])
    assert response.returncode == 1
    assert 'Usage:' in response.stderr


def test_mkfunding_bad_input_txid():
    response = subprocess_run(
        [EXECUTABLE,
         'alpha', 'beta', 'gamma', 'delta', 'epsilon',
         'zeta', 'eta'])
    assert response.returncode == 1
    assert 'Bad input-txid' in response.stderr


def test_mkfunding_bad_input_amount():
    response = subprocess_run(
        [EXECUTABLE,
         INPUT_TXID, INPUT_TXOUTPUT,
         'gamma', 'delta', 'epsilon', 'zeta', 'eta'])
    assert response.returncode == 1
    assert 'Bad input-amount' in response.stderr


def test_mkfunding_bad_input_privkey():
    response = subprocess_run(
        [EXECUTABLE,
         INPUT_TXID, INPUT_TXOUTPUT, INPUT_AMOUNT,
         FEERATE_PER_KW,
         'epsilon', 'zeta', 'eta'])
    assert response.returncode == 1
    assert 'Parsing input-privkey' in response.stderr


def test_mkfunding_bad_local_funding_privkey():
    response = subprocess_run(
        [EXECUTABLE,
         INPUT_TXID, INPUT_TXOUTPUT, INPUT_AMOUNT,
         FEERATE_PER_KW, INPUT_PRIVKEY,
         'zeta', 'eta'])
    assert response.returncode == 1
    assert 'Parsing local-funding-privkey' in response.stderr


def test_mkfunding_bad_remote_funding_privkey():
    response = subprocess_run(
        [EXECUTABLE,
         INPUT_TXID, INPUT_TXOUTPUT, INPUT_AMOUNT,
         FEERATE_PER_KW, INPUT_PRIVKEY,
         LOCAL_FUNDING_PRIVKEY,
         'eta'])
    assert response.returncode == 1
    assert 'Parsing remote-funding-privkey' in response.stderr


def test_mkfunding_bad_privkeys():
    bad_privkey = ('0' * 64)
    response = subprocess_run(
        [EXECUTABLE,
         INPUT_TXID, INPUT_TXOUTPUT, INPUT_AMOUNT,
         FEERATE_PER_KW,
         bad_privkey, bad_privkey, bad_privkey])
    assert response.returncode == 1
    assert 'Bad privkeys' in response.stderr


def test_mkfunding_bad_cantaffordfee():
    input_amount_less_than_fee = '0.00000122btc'
    response = subprocess_run(
        [EXECUTABLE,
         INPUT_TXID, INPUT_TXOUTPUT,
         input_amount_less_than_fee,
         FEERATE_PER_KW, INPUT_PRIVKEY,
         LOCAL_FUNDING_PRIVKEY, REMOTE_FUNDING_PRIVKEY])
    assert response.returncode == 1
    assert 'can\'t afford fee' in response.stderr


def test_mkfunding_good_noabort():
    response = subprocess_run(
        [EXECUTABLE,
         INPUT_TXID, INPUT_TXOUTPUT, INPUT_AMOUNT,
         FEERATE_PER_KW, INPUT_PRIVKEY,
         LOCAL_FUNDING_PRIVKEY, REMOTE_FUNDING_PRIVKEY])
    # prior to bug fix for issue #5363,
    # subprocess_run had a return code of -6 (abort)
    assert response.returncode == 0
    assert 'funding sig' in response.stdout
    assert 'funding witnesses' in response.stdout
    assert 'funding amount' in response.stdout
    assert 'funding txid' in response.stdout
