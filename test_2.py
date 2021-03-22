from myBlockchain import Blockchain, Transaction, Block
from time import time
import pprint

pp = pprint.PrettyPrinter(indent=4)

blockchain = Blockchain()

key = blockchain.generate_keys()

print(key)
print("")

blockchain.add_trans("Hue", "Moe", 10, key, key)
