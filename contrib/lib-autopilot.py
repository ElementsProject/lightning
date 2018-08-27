'''
Created on 26.08.2018

@author: rpickhardt

This program shall evolve to a python based rpc client for c-lighting. 
currently it can generate potential nodes according to 4 different strategies: 

# Random: following the Erdoes Renyi model nodes are drawn from a uniform distribution
# Central: nodes are sampled from a uniform distribution of the top most central nodes (betweenness)
# Network_Improovement: nodes are sampled from a uniform distribution of the nodes which are badly connected
# richness: nodes with high liquidity are taken and it is sampled from a uniform distribution of those

the programm needs the following dependencies:
pip install networkx pylightning
'''

"""
ideas: 
* channel balance of automatic channels should not be more than 50% of cummulative channel balance of destination node
* should we respect our own channel balances? 
* respect node life time / uptime? or time of channels? 
* include more statistics of the network: 
* allow autopilots of various nodes to exchange some information
* exchange algorithms if the network grows.
* include better handling for duplicates and existing channels
* cap number of channels for well connected nodes. 
"""

import logging

from lightning.lightning import LightningRpc
import json
import time
import pickle

import networkx as nx

import heapq
from operator import itemgetter
import random
import math

from os.path import expanduser

class Autopilot():
    __rpc_interface = None
    G = None 
    __logger = None
        
    def __init__(self):
        self.__add_logger()
        #FIXME: find out where the config file is placed:
        self.__rpc_interface = LightningRpc(expanduser("~")+"/.lightning/lightning-rpc")

        try:
            self.__logger.info("Try to load graph from file system at: data/networkx_graph")
            with open("data/networkx_graph","rb") as infile:
                self.G = pickle.load(infile)
                self.__logger.info("Successfully restored the lightning network graph from data/networkx_graph")
        except FileNotFoundError:
            self.__logger.info("load the graph from the peers of the lightning network")
        
            self.G = nx.Graph()
            if self.__load_nodes()==False:
                self.__logger.info("can not download nodes from the network and initialize the networkx Graph")
            if self.__load_edges()==False:
                self.__logger.info("cann not download the channels from the network and initialize the networkx Graph")
            else:
                with open("data/networkx_graph", "wb") as outfile:
                    pickle.dump(self.G,outfile,pickle.HIGHEST_PROTOCOL)
            
    def __add_logger(self):
        """ initiates the logging service for this class """
        #FIXME: adapt to the settings that are proper for you
        self.__logger = logging.getLogger('lib-autopilot')
        self.__logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.__logger.addHandler(ch)  
        # TODO: CHANGE from Console to file handler
        # fh = logging.FileHandler('lib-autopilot.log')
        # fh.setLevel(logging.DEBUG)
        #fh.setFormatter(formatter)
        #self.__logger.addHandler(fh)
        
    def __load_nodes(self):
        #FIXME: it is a real problem that we don't know how many nodes there could be
        nodes = []
        try:
            self.__logger.info("Attempt RPC-call to download nodes from the lightning network")
            while len(nodes) == 0: 
                peers = self.__rpc_interface.listpeers()["peers"]
                if len(peers) < 1:
                    #FIXME: do we have seed nodes?
                    self.__rpc_interface.connect("024a8228d764091fce2ed67e1a7404f83e38ea3c7cb42030a2789e73cf3b341365")
                    time.sleep(2)
                nodes = self.__rpc_interface.listnodes()["nodes"]
        except ValueError as e:
            self.__logger.info("Node list could not be retrieved from the peers of the lightning network")
            self.__logger.debug("RPC error: " + str(e))
            return False
        self.__logger.info("Number of nodes found: {}".format(len(nodes)))

        for node in nodes:
            self.G.add_node(node["nodeid"],**node)
        return True
    
    def __load_edges(self):
        """
        tries to store channels of the lightning network to the networkx graph. the attributes of the
        channel will be stored as edge attributes
        """
        if len(self.G.nodes)==0:
            self.__add_logger("cannot download channels if nodes do not exist. Try downloading the node list...")
            if self.__load_nodes() == False:
                self.add_logger("Stop trying to download channels")
                return False
        
        channels = {}
        try: 
            self.__logger.info("Attempt RPC-call to download channels from the lightning network")
            channels = self.__rpc_interface.listchannels()["channels"]
            self.__logger.info("Number of retrieved channels: {}".format(len(channels)))
        except ValueError as e:
            self.__logger.info("Channel list could not be retrieved from the peers of the lightning network")
            self.__logger.debug("RPC error: " + str(e))
            return False
        
        for channel in channels:
            self.G.add_edge(channel["source"],channel["destination"],**channel)
        
        return True

    def __generate_rich_nodes(self,k=3,percentile=0.5):
        """
            generates a set of nodes that are very well connected (such nodes with low degree will be prefered)
        """
        if k < 3:
            k = 3
        
        if percentile < 0.0 or percentile > 1.0:
            percentile = 0.5
        
        self.__logger.info("RICH_NODES: Try to generate {} candidates from the {}-percentile".format(k,percentile))
        
        rich_nodes = {}
        network_capacity = 0
        candidates = []
        for n in self.G.nodes():
            total_capacity = sum(self.G.get_edge_data(n,m)["satoshis"] for m in self.G.neighbors(n))
            network_capacity += total_capacity
            rich_nodes[n] = total_capacity
            
        cumsum = 0
        for n,value in sorted(rich_nodes.items(),key=itemgetter(1),reverse=True):
            cumsum +=value
            self.__logger.debug("RICH_NODES: node {} has {} neighbors and a balance of {}".format(n,value,len(list(self.G.neighbors(n)))))
            candidates.append(n)
            if cumsum > network_capacity*percentile:
                break 
        
        self.__logger.info("RICH_NODES: Found {} candidates in the {}-percentile".format(len(candidates),percentile))        
        if len(candidates) <= k:
            return list(candidates)
        self.__logger.info("RICH_NODES: Sample {} items from the candidates as was requested".format(k))
        tmp = list(candidates)
        random.shuffle(tmp)
        return tmp[0:k]
        
    def __generate_central_nodes(self,k=3):
        """
            generates a set of nodes that are very well connected (such nodes with low degree will be prefered)
            uses the betweenness centrality. 
            #FIXME: not sure if this is even helpfull. I imagein that one would not want to connect to those. it is good since it keeps diameter small but it is bad as it makes the network depend on those
        """
        if k < 3:
            k = 3
            
        self.__logger.info("CENTRAL_NODES: Try to seek {} nodes which are currently central".format(k))        
        res = [n for n,_ in sorted(nx.betweenness_centrality(self.G).items(),key=itemgetter(1),reverse=True)[:4*k]]
        self.__logger.info("CENTRAL_NODES: Generated top {} central nodes (according to betweeness centrality)".format(len(res)))
        
        self.__logger.info("CENTRAL_NODES: Sample {} items from the candidates as was requested".format(k))
        tmp = list(res)
        random.shuffle(tmp)
        return tmp[0:k]

    def __generate_random_nodes(self,k=3):
        """
            generates a random set of nodes.
            
            this assumes a uniform distribution of all nodes. 
        """
        if k < 3:
            k = 3

        k = min(k,len(self.G.nodes()))
        self.__logger.info("RANDOM_NODES: try to generate a set of {} nodes sampled with uniform distribution".format(k))
        
        return random.sample(self.G.nodes(),k)
    
    def __generate_connicticity_increasing_canidates(self,k=3):
        """
            generates a set of nodes that are not well connected
            for this the start end end nodes of longest paths are retrieved
        """
        result = set()
        
        if k < 3:
            k = 3
        
        self.__logger.info("IMPROOVE_NETWORK: Try to seek {} nodes which are currently bad connected".format(k))
        candidates = heapq.nlargest(3*k, self.__generate_all_shortest_paths(), key=itemgetter(0))

        for _, path in candidates:
            result.add(path[0])
            result.add(path[-1])

        self.__logger.info("IMPROOVE_NETWORK: Found {} candidates which are currently bad connected".format(len(result)))        
        if len(result) <= k:
            return list(result)
        self.__logger.info("IMPROOVE_NETWORK: Sample {} items from the candidates as was requested".format(k))
        tmp = list(result)
        random.shuffle(tmp)
        return tmp[0:k]
        
 
    def __generate_all_shortest_paths(self,cutoff = 10):
        """ 
        this is basically a wrapper for nx.all_pair_shortest_path to have a more convenient output format
        
        generates all shortest paths and yields each item, the format of the output is
        (len, [src, n1,...,n_{m-2}, dest])
        """
        if cutoff < 1:
            cutoff = 10
            self.__logger.info("cutoff value must be a positive integer. Set back to default value: 10")

        all_pair_shortest_paths = nx.all_pairs_shortest_path(self.G, cutoff=cutoff)
        for item in all_pair_shortest_paths:
            from_node = item[0]
            paths = item[1]
            for destination,path in paths.items():
                yield (len(path),path)
                    
    
    def __display_nodes(self,nodes):
        for node in nodes:
            if "alias" in self.G.node[node]:
                print(self.G.node[node]["alias"])
            else:
                print(node)
    def get_candidates(self,k=10):
        sub_k = math.ceil(k/4)
        self.__logger.info("GENERATE CANDIDATES: Try to generate up to {} nodes with 4 strategies: (random, central, network Improvement, liquidity)")
        candidats = set()
        res = self.__generate_random_nodes(sub_k)
        candidats=candidats.union(set(res))
        res = self.__generate_central_nodes(sub_k)
        candidats=candidats.union(set(res))
        res = self.__generate_rich_nodes(sub_k)
        candidats=candidats.union(set(res))
        res = self.__generate_connicticity_increasing_canidates(sub_k)
        candidats=candidats.union(set(res))

        if len(candidats) > k:
            tmp = list(candidats)
            random.shuffle(tmp)
            candidats = tmp[:k]
        
        self.__logger.info("GENERATE CANDIDATES: Found {} nodes with which channel creation is suggested".format(len(candidats)))
        return candidats
            
    
    def run(self):
        self.__logger.info("running the autopilot on a graph with {} nodes and {} edges.".format(len(self.G.nodes()), len(self.G.edges())))
        candidates = self.get_candidates(k=21)
        time.sleep(1)
        self.__display_nodes(list(candidates))
        



if __name__ == '__main__':
    autopilot = Autopilot()
    autopilot.run()