import sys
import socket
import pickle
import os
import logging
import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import DES3

__author__ = 'Umair'


class Alice():
    def __init__(self, host, port):
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            logging.warning("Could not create socket")
            exit()
        self.buff_size = 8192
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

    # Adds padding to the string so it can be encrypted
    def add_padding(self, enc_str):
        block_size = 8
        padding = '{'
        if len(enc_str) % block_size != 0:
            padding_amount = block_size - (len(enc_str) % block_size)
            for x in range(0, padding_amount):
                enc_str += padding
        return enc_str

    def generate_digital_signature(self, message):
        h = SHA.new(message)
        r_str = os.urandom(8)
        ds = self.private_key.encrypt(h.digest(), r_str)
        return [ds, message]

    # Generates and returns a 3DES symmetric key
    def generate_symmetric_key(self, key):
        str_size = 8
        iv = os.urandom(str_size)
        return DES3.new(key, DES3.MODE_CBC, iv)

    # Connect to the server
    def connect(self, key):
        address = (self.host, self.port)
        self.client.connect(address)
        self.client.setblocking(0)

        buff = ''
        kc_public = self.load_ca_public_key()

        # begin the timer
        timeout = 1
        begin = time.time()
        while True:
            if buff and time.time()-begin > timeout:
                break

            # recv the data
            try:
                data = self.client.recv(self.buff_size)
                if data:
                    buff += data
                else:
                    time.sleep(0.1)
            except:
                pass

        # Unpickle the digital signature object
        ds = pickle.loads(buff)

        # Verify the digital signature
        h = SHA.new(ds[0])
        verifier = PKCS1_v1_5.new(kc_public)
        if verifier.verify(h, ds[1]):
            print "Successfully verified Bob's public key"
            self.bob_public_key = RSA.importKey(ds[0])

            # Generate digital signature and symmetric key
            ds = self.generate_digital_signature("Hi Bob, this is Alice")
            triple_des = self.generate_symmetric_key(key)
            ds_serialized = pickle.dumps(ds)
            ds_str = self.add_padding(ds_serialized)

            print "Length of ds obj {}".format(len(ds_str))
            # Encrypt digital signature with 3DES
            ds_enc = triple_des.encrypt(ds_str)
            session_key = self.bob_public_key.encrypt(''.join(ds_enc), 256)
            block = [ds_enc, session_key]
            payload = pickle.dumps(block)

            self.client.sendall(payload)
            logging.info("Finished transmitting encrypted data to Bob.\nClosing connection.")
            self.client.shutdown
        else:
            print "It's a trap! Cannot verify Bob's key."
            self.client.close()
            return False


def main(argv):
    host = ''
    port = 4112
    key = os.urandom(16)
    alice = Alice(host,port)
    alice.connect(key)


if __name__ == '__main__':
    main(sys.argv[1:])

