from myBlockchain import *
import time
import pprint

pp = pprint.PrettyPrinter(indent = 4)

"""
in blockchian_try.py
 def adding(self, block):
        if len(self.chain) > 0:
            block.pre_hash = self.chain[-1].hash
        else:
            block.pre_hash = "none"
        self.chain.append(block)
"""

blockchain = Blockchain()
transactions = []

block_1 = Block(time.time(), transactions, 0)
blockchain.adding(block_1)

block_2 = Block(time.time(), transactions, 1)
blockchain.adding(block_2)

block_3 = Block(time.time(), transactions, 2)
blockchain.adding(block_3)

pp.pprint(blockchain.chain_json_encode())
print(len(blockchain.chain))
