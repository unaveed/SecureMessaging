import sys
import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5

__author__ = 'Umair'

class Alice():
    def __init__(self, host, port):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recv_size = 8192
        self.host = host
        self.port = port
        self.public_key = self.load_public_key()
        self.private_key = self.load_private_key()
        self.cert_key = self.load_ca_public_key()
        self.bob_public_key = None

    @staticmethod
    def load_ca_public_key():
        with open('../keys/capublickey.pem', 'r') as key:
            data = key.read()
        return RSA.importKey(data)

    @staticmethod
    def load_public_key():
        with open('../keys/alicepublickey.pem', 'r') as key:
            data = key.read()
        return RSA.importKey(data)

    @staticmethod
    def load_private_key():
        with open('../keys/aliceprivatekey.pem', 'r') as key:
            data = key.read()
        return RSA.importKey(data)


    def generate_block(self):
        return None

    # Connect to the server
    def connect(self):
        address = (self.host, self.port)
        self.client.connect(address)
        buff = ''
        key = self.load_ca_public_key()

        while True:
            data = self.client.recv(self.recv_size)
            print data
            if not data or 'end' in data:
                break
            buff += data

        # Unpickle the digital signature object
        ds = pickle.loads(buff)

        # Verify the digital signature
        h = SHA.new(ds[0])
        verifier = PKCS1_v1_5.new(key)
        if verifier.verify(h, ds[1]):
            print "Successfully verified Bob's public key"
            self.bob_public_key = ds[0]
            block = self.generate_block()

        else:
            print "It's a trap! Cannot verify Bob's key."
            self.client.close()
            return False


def main(argv):
    host = ''
    port = 4112
    alice = Alice(host,port)
    alice.connect()


if __name__ == '__main__':
    main(sys.argv[1:])

