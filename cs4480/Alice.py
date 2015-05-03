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
            logging.error("Could not create socket")
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
        logging.info("Alice: Loaded certificate authority public key")
        return RSA.importKey(data)

    @staticmethod
    def load_public_key():
        with open('../keys/alicepublickey.pem', 'r') as key:
            data = key.read()
        logging.info("Alice: Loaded public key")
        return RSA.importKey(data)

    @staticmethod
    def load_private_key():
        with open('../keys/aliceprivatekey.pem', 'r') as key:
            data = key.read()
        logging.info("Alice: Loaded private key")
        return RSA.importKey(data)

    # Adds padding to the string so it can be encrypted
    def add_padding(self, enc_str):
        block_size = 8
        padding = '{'
        if len(enc_str) % block_size != 0:
            logging.info("Alice: Adding padding to string as it's not a multiple of {}".format(block_size))
            padding_amount = block_size - (len(enc_str) % block_size)
            for x in range(0, padding_amount):
                enc_str += padding
        return enc_str

    def generate_digital_signature(self, message):
        h = SHA.new(message)
        signer = PKCS1_v1_5.new(self.private_key)
        ds = signer.sign(h)
        logging.info("Alice: Generated digital signature.")
        return [ds, message]

    # Generates and returns a 3DES symmetric key and parameters for key
    def generate_symmetric_key(self, key):
        str_size = 8
        iv = os.urandom(str_size)
        logging.info("Alice: Generated 3DES symmetric key")
        return [DES3.new(key, DES3.MODE_CBC, iv), key, DES3.MODE_CBC, iv]

    # Connect to the server
    def connect(self, key):
        address = (self.host, self.port)
        self.client.connect(address)
        self.client.setblocking(0)
        logging.info("Alice: Connected to {}".format(address))

        buff = ''
        kc_public = self.load_ca_public_key()

        # begin the timer
        timeout = 1
        begin = time.time()
        while True:
            if buff and time.time()-begin > timeout:
                break

            # receive the data
            try:
                data = self.client.recv(self.buff_size)
                if data:
                    buff += data
                else:
                    time.sleep(0.1)
            except:
                pass

        # Unpickle the digital signature object
        try:
            ds = pickle.loads(buff)
        except:
            logging.error("Alice: Unable to unpickle object, exiting")
            sys.exit()

        logging.info("Alice: Unpickled object.")
        # Verify the digital signature
        h = SHA.new(ds[0])
        verifier = PKCS1_v1_5.new(kc_public)
        if verifier.verify(h, ds[1]):
            logging.info("Alice: Successfully verified Bob's digital signature, obtained Bob's public key.")
            self.bob_public_key = RSA.importKey(ds[0])

            # Generate digital signature and symmetric key
            try:
                message = raw_input("Enter message: ")
            except EOFError:
                logging.warning("Unable to read user input, using default message")
                message = "Hi Bob this is Alice"

            ds = self.generate_digital_signature(message)
            triple_des = self.generate_symmetric_key(key)
            ds_serialized = pickle.dumps(ds)
            ds_str = self.add_padding(ds_serialized)

            # Encrypt digital signature with 3DES
            dig_sig = triple_des[0].encrypt(ds_str)
            session_key_bundle = [self.bob_public_key.encrypt(''.join(dig_sig), 256),
                                  triple_des[1], triple_des[2], triple_des[3]]

            block = [dig_sig, session_key_bundle]

            try:
                payload = pickle.dumps(block)
            except:
                logging.error("Alice: Unable to pickle package, exiting")
                sys.exit()

            self.client.sendall(payload)
            logging.info("Sent encrypted bundle to Bob. Closing connection.")
            self.client.shutdown
            self.client.close()
            return True
        else:
            logging.info("Alice: Unable to verify Bob's key and/or digital signature, closing connection.")
            self.client.close()
            return False


def main(argv):
    host = ''
    port = 4112
    key = os.urandom(16)

    host_cmd = False
    port_cmd = False
    key_cmd = False
    for arg in argv:
        if arg == '-h':
            message = "Usage: python Alice.py [-v verbose] [-r host-name] "
            message += "[-p port] [-k secret-key]"
            print message
        if arg == '-v':
            root = logging.getLogger()
            root.setLevel(logging.INFO)
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            root.addHandler(ch)
        if arg == '-r':
            host_cmd = True
        if arg == '-p':
            port_cmd = True
        if arg == '-k':
            key_cmd = True
        if host_cmd:
            host = arg
            host_cmd = False
        if port_cmd:
            port = arg
            port_cmd = False
        if key_cmd:
            if len(arg) != 16 or len(arg) != 8:
                print "Key must be 8 or 16 bytes, using default key"
            else:
                key = arg
            key_cmd = False

    alice = Alice(host,port)
    alice.connect(key)


if __name__ == '__main__':
    main(sys.argv[1:])

