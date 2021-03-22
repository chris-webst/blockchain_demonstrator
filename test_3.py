from Crypto.PublicKey import RSA
from Crypto.Signature import *

def generate_keys():
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out =  open("private.pem", "wb")
        file_out.write(private_key)
    
        public_key = key.publickey().export_key()
        file_out = open("receiver.pem", "wb")
        file_out.write(public_key)


        return (private_key, public_key)

print(generate_keys())