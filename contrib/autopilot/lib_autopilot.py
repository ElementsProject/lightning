'''
Created on 26.08.2018

@author: rpickhardt

lib_autopilot is a library which based on a networkx graph tries to 
predict which channels should be added for a new node on the network. The
long term is to generate a lightning network with good topological properties.

This library currently uses 4 heuristics to select channels and supports
two strategies for combining those heuristics. 
1.) Diverse: which tries to to get nodes from every distribution
2.) Merge: which builds the mixture distribution of the 4 heuristics

The library also estimates how much funds should be used for every newly
added channel. This is achieved by looking at the average channel capacity
of the suggested channel partners. A probability distribution which is 
proportional to those capacities is created and smoothed with the uniform
distribution. 

The 4 heuristics for channel partner suggestion are: 

1.) Random: following the Erdoes Renyi model nodes are drawn from a uniform 
distribution
2.) Central: nodes are sampled from a distribution proportional to the 
betweeness centrality of nodes
3.) Decrease Diameter: nodes are sampled from distribution of the nodes which 
favors badly connected nodes
4.) Richness: nodes with high liquidity are taken and it is sampled from a 
uniform distribution of those

The library is supposed to be extended by a simulation framework which can 
be used to evaluate which strategies are useful on the long term. For this
heavy computations (like centrality measures) might have to be reimplemented
in a more dynamic way. 

Also it is important to understand that this program is not optimized to run
efficiently on large scale graphs with more than 100k nodes or on densly 
connected graphs.

the programm needs the following dependencies:
pip install networkx numpy
'''
"""
ideas:
* should we respect our own channel balances?
* respect node life time / uptime? or time of channels?
* include more statistics of the network:
* allow autopilots of various nodes to exchange some information
* exchange algorithms if the network grows.
* include better handling for duplicates and existing channels
* cap number of channels for well connected nodes.
* channel balance of automatic channels should not be more than 50% of 
cummulative channel balance of destination node


next steps: 
* test if the rankings from the heuristics are statistically independent
* evaluate / simulate which method produces graphs with desirable properties
"""

from operator import itemgetter
import logging
import math
import pickle


import networkx as nx
import numpy as np

class Strategy:
    #define constants. Never changed as they are part of the API
    DIVERSE = "diverse"
    MERGE = "merge"    

class Autopilot():

    def __init__(self,G):
        self.__add_logger()        
        self.G = G

    def __add_logger(self):
        """ initiates the logging service for this class """
        # FIXME: adapt to the settings that are proper for you
        self.__logger = logging.getLogger('lib-autopilot')
        self.__logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.__logger.addHandler(ch)

    def __sample_from_pdf(self,pdf,k=21):
        """
        helper function to quickly sample from a pdf encoded in a dictionary
        """
        if type(k) is not int:
            raise TypeError("__sample_from: k must be an integer variable")
        if k < 0 or k > 21000:
            raise ValueError("__sample_from: k must be between 0 and 21000")
        
        keys,v = zip(*list(pdf.items()))
        if k>=len(keys):
            return keys
        res = np.random.choice(keys, k, replace=False, p=v)
        return res
    
    def __sample_from_percentile(self, pdf, percentile=0.5, num_items=21):
        """
        only look at the most likely items and sample from those
        """
        if not percentile:
            return self.__sample_from_pdf(pdf,num_items)

        if type(percentile) is not float:
            raise TypeError("percentile must be a floating point variable")
        if percentile < 0 or percentile > 1:
            raise ValueError("percentile must be btween 0 and 1")
                
        cumsum = 0
        used_pdf = {}
        for n, value in sorted(
                pdf.items(), key=itemgetter(1), reverse=True):
            cumsum += value
            used_pdf[n] = value
            if cumsum > percentile:
                break
            
        used_pdf = {k:v/cumsum for k, v in used_pdf.items()}
        return self.__sample_from_pdf(used_pdf, num_items)
       
    def __get_uniform_pdf(self):
        """
        Generates a uniform distribution of all nodes in the graph
        
        In opposite to other methods there are no arguments for smoothing
        or skewing since this would not do anything to the uniform
        distribution
        """
        pdf = {n:1 for n in self.G.nodes()}
        length = len(pdf)
        return {k:v/length for k, v in pdf.items()}
        
    def __get_centrality_pdf(self, skew = False, smooth = False):
        """
        produces a probability distribution which is proportional to nodes betweeness centrality scores
        
        the betweeness centrality counts on how many shortest paths a node is
        connecting to thos nodes will most likely make them even more central
        however it is good for the node operating those operation as this node
        itself gets a position in the network which is close to central nodes
        
        this distribution can be skewed and smoothed
        """
        self.__logger.info(
            "CENTRALITY_PDF: Try to generate a PDF proportional to centrality scores")
        pdf = {}
        cumsum = 0
        for n, score in nx.betweenness_centrality(self.G).items():
            pdf[n] = score
            cumsum += score
            
        #renoremalize result
        pdf = {k:v/cumsum for k, v in pdf.items()}
        self.__logger.info(
            "CENTRALITY_PDF: Generated pdf")
        
        if skew and smooth:
            self.__logger.info(
            "CENTRALITY_PDF: Won't skew and smooth distribution ignore both")
            smooth = False
            skew = False
        return self.__manipulate_pdf(pdf, skew, smooth)
    
    def __get_rich_nodes_pdf(self,skew=False,smooth=False):
        """
        Get a PDF proportional to the cummulative capacity of nodes
        
        The probability density function is calculated by looking at the
        cummulative capacity of all channels one node is part of. 
            
        The method will by default skew the pdf by taking the squares of the
        sums of capacitoes after deriving a pdf. If one whishes the method
        can also be smoothed by taking the mixture distribution with the
        uniform distribution
        
        Skewing and smoothing is controlled via the arguments skew and smooth 
        """
        self.__logger.info(
            "RICH_PDF: Try to retrieve a PDF proportional to capacities")

        rich_nodes = {}
        network_capacity = 0
        candidates = []
        for n in self.G.nodes():
            total_capacity = sum(
                self.G.get_edge_data(
                    n, m)["satoshis"] for m in self.G.neighbors(n))
            network_capacity += total_capacity
            rich_nodes[n] = total_capacity

        rich_nodes = {k:v/network_capacity for k, v in rich_nodes.items()}

        self.__logger.info(
            "RICH_PDF: Generated a PDF proportional to capacities")
        
        
        if skew and smooth:
            self.__logger.info(
            "RICH_PDF: Can't skew and smooth distribution ignore both")
            smooth = False
            skew = False
        
        return self.__manipulate_pdf(rich_nodes, skew, smooth)


    def __get_long_path_pdf(self,skew=True,smooth=False):
        """
        A probability distribution in which badly connected nodes are likely
        
        This method looks at all pairs shortest paths and takes the sum of all
        path lenghts for each node and derives the a probability distribution
        from the sums. The idea of this method is to find nodes which are 
        increasing the diameter of the network.
        
        The method will by default skew the pdf by taking the squares of the
        sums of path lengths before deriving a pdf. If one whishes the method
        can also be smoothed by taking the mixture distribution with the
        uniform distribution
        
        Skewing and smoothing is controlled via the arguments skew and smooth      
        """
        if skew and smooth:
            self.__logger.info(
            "DECREASE DIAMETER: Can't skew and smooth distribution ignore smoothing")
            smooth = False
                
        path_pdf = {}
        self.__logger.info(
            "DECREASE DIAMETER: Generating probability density function")

        all_pair_shortest_path_lengths = nx.shortest_path_length(self.G)

        for node, paths in all_pair_shortest_path_lengths:
            path_sum = sum(length for _, length in paths.items())
            path_pdf[node] = path_sum
        
        s = sum(path_pdf.values())
        path_pdf = {k:v/s for k,v in path_pdf.items()}
        self.__logger.info(
            "DECREASE DIAMETER: probability density function created")

        path_pdf = self.__manipulate_pdf(path_pdf, skew, smooth)
        
        return path_pdf
    
    def __manipulate_pdf(self, pdf, skew=True, smooth=False):
        """ 
        helper function to skew or smooth a probability distribution
        
        skewing is achieved by taking the squares of probabilities and 
        re normalize
        
        smoothing is achieved by taking the mixture distribution with the
        uniform distribution
        
        smoothing and skewing are not inverse to each other but should also
        not happen at the same time. The method will however not prevent this
        """
        if not skew and not smooth: #nothing to do
            return pdf
        length = len(pdf)
        if skew:
            self.__logger.info(
            "manipulate_pdf: Skewing the probability density function")
            pdf = {k:v**2 for k,v in pdf.items()}
            s = sum(pdf.values())
            pdf = {k:v/s for k,v in pdf.items()}
        
        if smooth:
            self.__logger.info(
            "manipulate_pdf: Smoothing the probability density function")
            pdf = {k:0.5*v + 0.5/length for k,v in pdf.items()}
            
        return pdf

    def __create_pdfs(self):
        res = {}
        res["path"] = self.__get_long_path_pdf()
        res["centrality"] = self.__get_centrality_pdf()
        res["rich"] = self.__get_rich_nodes_pdf()
        res["uniform"] = self.__get_uniform_pdf()
        return res
        


    def calculate_statistics(self, candidates):
        """
        computes statistics of the candidate set about connectivity, wealth 
        and returns a probability density function (pdf) which encodes which 
        percentage of the funds should be used for each channel with each 
        candidate node

        the pdf is proportional to the average balance of each candidate and 
        smoothed with a uniform distribution currently the smoothing is just a
         weighted arithmetic mean with a weight of 0.3 for the uniform 
         distribution.
        """
        pdf = {}
        for candidate in candidates:
            neighbors = list(self.G.neighbors(candidate))
            capacity = sum([self.G.get_edge_data(candidate, n)
                            ["satoshis"] for n in neighbors])
            average = capacity / (1+len(neighbors))
            pdf[candidate] = average
        cumsum = sum(pdf.values())
        pdf = {k: v / cumsum for k, v in pdf.items()}
        w = 0.7
        print("percentage   smoothed percentage    capacity    numchannels     alias")
        print("----------------------------------------------------------------------")
        res_pdf = {}
        for k, v in pdf.items():
            neighbors = list(self.G.neighbors(k))
            capacity = sum([self.G.get_edge_data(k, n)["satoshis"]
                            for n in neighbors])
            name = k
            if "alias" in self.G.node[k]:
                name = self.G.node[k]["alias"]
            print("{:12.2f}  ".format(100 * v),
                  "{:12.2f}     ".format(
                      100 * (w * v + (1 - w) / len(candidates))),
                  "{:10} {:10}     ".format(capacity,
                                            len(neighbors)),
                  name)
            res_pdf[k] = (w * v + (1 - w) / len(candidates))
        return res_pdf

    def calculate_proposed_channel_capacities(self, pdf, balance=1000000):
        minimal_channel_balance = 20000  # lnd uses 20k satoshi which seems reasonble

        min_probability = min(pdf.values())
        needed_total_balance = math.ceil(
            minimal_channel_balance / min_probability)
        self.__logger.info(
            "Need at least a balance of {} satoshi to open {} channels".format(
                needed_total_balance, len(pdf)))
        while needed_total_balance > balance and len(pdf) > 1:
            min_val = min(pdf.values())
            k = [k for k, v in pdf.items() if v == min_val][0]
            self.__logger.info(
                "Not enough balance to open {} channels. Remove node: {} and rebalance pdf for channel balances".format(
                    len(pdf), k))
            del pdf[k]

            s = sum(pdf.values())
            pdf = {k: v / s for k, v in pdf.items()}

            min_probability = min(pdf.values())
            needed_total_balance = math.ceil(
                minimal_channel_balance / min_probability)
            self.__logger.info(
                "Need at least a balance of {} satoshi to open {} channels".format(
                    needed_total_balance, len(pdf)))

        return pdf



    def find_candidates(self, num_items=21,strategy = Strategy.DIVERSE, 
                        percentile = None):
        self.__logger.info("running the autopilot on a graph with {} nodes and {} edges.".format(
            len(self.G.nodes()), len(self.G.edges())))
        """
        Generates candidates with several strategies
        """
        sub_k = math.ceil(num_items / 4)
        self.__logger.info(
            "GENERATE CANDIDATES: Try to generate up to {} nodes with 4 strategies: (random, central, network Improvement, liquidity)".format(num_items))
        # FIXME: should remember from where nodes are known
        
        res = self.__create_pdfs()
        
        candidats = set()
        # FIXME: Run simulations to decide the following problem:
        """
        we can either do a global sampling by merging all probability 
        distributions and sample once from them or we can sample from 
        each probability distribution and merge the results. These processes
        are obviously not commutative and we need to check which one seems
        more reasonable.
        My (renepickhardt) guts feeling says several samples which are 
        merged gives the best of all worlds where the other method would 
        probably result in something that is either pretty uniform or 
        dominated by one very skew distribution. as mentioned this needs
        to be tested
        """
        if strategy == Strategy.DIVERSE:
            for strategy, pdf in res.items():
                tmp = self.__sample_from_percentile(pdf, percentile, sub_k)
                candidats = candidats.union(set(tmp))
                
        elif strategy == Strategy.MERGE:
            merged = {}
            denominator = len(res)
            for pdf in res.values():
                for k, v in pdf.items():
                    if k not in merged:
                        merged[k] = v/denominator
                    else:
                        merged[k] += v/denominator
            candidats = self.__sample_from_percentile(merged, percentile, 
                                                      num_items)
        """
        following code prints a list of candidates for debugging
        for k in res:
            if "alias" in self.G.node[key[k]]:
                print(pdf[key[k]], self.G.node[key[k]]["alias"])
        """

        if len(candidats) > num_items:
            candidats = np.random.choice(list(candidats), num_items, replace=False)

        self.__logger.info(
            "GENERATE CANDIDATES: Found {} nodes with which channel creation is suggested".format(
                len(candidats)))
        return candidats

if __name__ == '__main__':
    print("This lib needs to be given a network graph so you need to create a wrapper")
