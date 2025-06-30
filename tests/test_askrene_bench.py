from fixtures import *  # noqa: F401,F403
from hashlib import sha256
from pyln.client import RpcError
from pyln.testing.utils import SLOW_MACHINE
from utils import (
    only_one, first_scid, GenChannel, generate_gossip_store,
    sync_blockheight, wait_for, TEST_NETWORK, TIMEOUT
)
import os
import pytest
import subprocess
import time
import tempfile
import random
import json

@pytest.mark.slow_test
def test_real_data(node_factory, bitcoind):
    outfile = tempfile.NamedTemporaryFile(prefix='gossip-store-')
    nodeids = subprocess.check_output(['devtools/gossmap-compress',
                                       'decompress',
                                       'tests/data/gossip-store-2024-09-22.compressed',
                                       outfile.name]).decode('utf-8').splitlines()

    # This is in msat, but is also the size of channel we create.
    AMOUNT = 100000000

    l1 = node_factory.line_graph(1, fundamount=AMOUNT,
                                     opts=[{'gossip_store_file': outfile.name,
                                            'allow_warning': True,
                                            'dev-throttle-gossip': None}])[0]

    # node selection
    all_nodes = []
    all_chans = l1.rpc.listchannels()["channels"]
    
    node_dict = {}
    for c in all_chans:
        n = c["source"]
        if n not in node_dict:
            node_dict[n] = {"id": n, "num_chans": 0, "capacity": 0}
        node_dict[n]["num_chans"] += 1
        node_dict[n]["capacity"] += c["amount_msat"]
    
    all_nodes = [ data for n, data in node_dict.items() ]
    
    # def big_node(n):
    #     return n['num_chans']>=50 and n['num_chans']<=100 \
    #         and n['capacity']<=2*1e11 and n['capacity']>=1*1e11
    # 
    # def small_node(n):
    #     return n['num_chans']>=2 and n['num_chans']<=5 \
    #         and n['capacity']<=0.2*1e11 and n['capacity']>=0.1*1e11
    # 
    # all_big = [n for n in all_nodes if big_node(n)]
    # all_small = [n for n in all_nodes if small_node(n)]
    
    all_nodes.sort(key=lambda n: n["capacity"])
    print(all_nodes[:10])
    
    N = len(all_nodes)
    all_small = all_nodes[int(0.10*N): int(0.35 * N)]
    all_big = all_nodes[int(0.65*N): int(0.90*N)]
    
    print("big nodes:", len(all_big))
    print("small nodes:", len(all_small))
    
    # cts.sort()
    # min_val = cts[0]
    # max_val = cts[-1]
    # freq = np.zeros(max_val+1, dtype=int)
    # for i in cts:
    #     freq[i] += 1
    # print(list(freq))
    # plt.hist(cts, bins=20, range=(10, 100))
    # plt.savefig('foo.png')
    
    random.seed(42)
    amounts = [100, 1000, 10000, 100000, 1000000]
    num_samples = 100 
    datapoints = []
    
    def routes_fee(routes):
        pay = 0
        deliver = 0
        for r in routes["routes"]:
            deliver += r["amount_msat"]
            pay += r["path"][0]["amount_msat"]
        return pay - deliver
    
    def run_sim(node_set, amt_msat, repeat, version, sample_name, data):
        for _ in range(repeat):
            # 0.5% or 5sat is the norm
            MAX_FEE = max(amt_msat // 200, 5000)
            src_index = random.randint(0, len(node_set)-1)
            dst_index = src_index
            while dst_index==src_index:
                dst_index = random.randint(0, len(node_set)-1)
            try:
                resp = l1.rpc.getroutes(source=nodeids[src_index],
                                        destination=nodeids[dst_index],
                                        amount_msat=amt_msat,
                                        layers=[],
                                        maxfee_msat=MAX_FEE,
                                        final_cltv=18)
                success = True
            except RpcError as e:
                success = False
                resp = e.error
            line = l1.daemon.wait_for_log(
                "plugin-cln-askrene.*notify msg.*get_routes (completed|failed)")
            runtime = int(line.split()[-2])
            this_data = {"runtime_msec": runtime, "amount_msat": amt_msat, 
                "version": version,
                "sample": sample_name, "success": success}
            if success:
                this_data["probability"] = resp["probability_ppm"] * 1e-6
                this_data["fee_msat"] = routes_fee(resp)
            else:
                this_data["probability"] = 0.0
                this_data["fee_msat"] = 0
            print(resp)
            data.append(this_data)
    for amt_sat in amounts:
        run_sim(all_big, amt_sat*1000, num_samples, "default", "big", datapoints)
        run_sim(all_small, amt_sat*1000, num_samples, "default", "small", datapoints)
    with open("default_bench.json", "w") as fd:
        json.dump(datapoints, fd)
