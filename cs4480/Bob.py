import sys, logging
import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Cipher import DES3

__author__ = 'Umair'


class Bob:
    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.buff_size = 4096
        self.private_key = self.load_bob_private_key()
        self.public_key = self.load_bob_public_key()
        self.alice_key = self.load_alice_public_key()
        self.cert_public_key = self.load_ca_public_key()
        self.cert_private_key = self.load_ca_private_key()
        self.host = host
        self.port = port

    @staticmethod
    def load_bob_private_key():
        # Load the keys
        with open('../keys/bobprivatekey.pem', 'r') as key:
            data = key.read()
        logging.info("Bob: Imported Bob's private key")
        return RSA.importKey(data)


    @staticmethod
    def load_bob_public_key():
        with open('../keys/bobpublickey.pem', 'r') as key:
            data = key.read()
        logging.info("Bob: Imported Bob's public key")
        return RSA.importKey(data)


    @staticmethod
    def load_alice_public_key():
        with open('../keys/alicepublickey.pem', 'r') as key:
            data = key.read()
        logging.info("Bob: Imported Alice's public key")
        return RSA.importKey(data)


    @staticmethod
    def load_ca_private_key():
        with open('../keys/caprivatekey.pem', 'r') as key:
            data = key.read()
        logging.info("Bob: Imported CA private key")
        return RSA.importKey(data)


    @staticmethod
    def load_ca_public_key():
        with open('../keys/capublickey.pem', 'r') as key:
            data = key.read()
        logging.info("Bob: Imported CA public key")
        return RSA.importKey(data)

    def get_session_key(self, session_key_bundle):
        key = session_key_bundle[1]
        mode = session_key_bundle[2]
        iv = session_key_bundle[3]
        logging.info("Bob: Re-created 3DES key from senders package")
        return DES3.new(key, mode, iv)

    def remove_padding(self, enc_str):
        block_size = 8
        padding = '{'
        logging.info("Bob: Removing padding from pickled object")
        return enc_str.strip(padding)

    def generate_digital_signature(self, signer_key, encryption_key):
        signer = PKCS1_v1_5.new(encryption_key)
        digest = SHA.new(signer_key)
        logging.info("Bob: Generated digital signature for given key")
        return signer.sign(digest)

    def start_server(self, host, port):
        logging.info("Bob: Socket created")

        self.server.bind((host, port))
        logging.info('Bob: Socket bind complete')
        self.server.listen(1)

    def run(self):
        key = self.public_key.exportKey()

        digest = self.generate_digital_signature(key, self.cert_private_key)
        ds = [key, digest]

        try:
            digest_obj = pickle.dumps(ds)
        except:
            logging.ERROR("Bob: Could not pickle message digest, exiting.")
            sys.exit()

        buff = ''
        self.start_server(self.host, self.port)
        while 1:
            conn, client = self.server.accept()

            logging.info('Bob: Connected with ' + client[0] + ": " + str(client[1]))
            conn.sendall(digest_obj)
            logging.info("Bob: Transmitted public key")

            try:
                while True:
                    data = conn.recv(self.buff_size)
                    if not data:
                        break
                    buff += data
            finally:
                conn.close()

            try:
                payload = pickle.loads(buff)
                logging.info("Bob: Loaded encrypted package from sender.")
            except:
                logging.ERROR("Bob: Unable to unpickle object, exiting.")
                sys.exit()

            ds = payload[0]
            symmetric_key = self.get_session_key(payload[1])
            logging.info("Bob: Retrieved symmetric key from package.")

            padded_str = symmetric_key.decrypt(ds)
            pickled_obj = self.remove_padding(padded_str)

            try:
                digital_signature = pickle.loads(pickled_obj)
                logging.info("Bob: Unpickled digital signature")
            except:
                logging.ERROR("Bob: Could not unpickle digital signature, exiting")
                sys.exit()

            h = SHA.new(digital_signature[1])
            verifier = PKCS1_v1_5.new(self.alice_key)
            if verifier.verify(h, digital_signature[0]):
                logging.info("Bob: Successfully verified Alice's digital signature")
                print 'Alice says: ' + digital_signature[1]
            else:
                print "The message has been tampered with"

            conn.close()
            conn.shutdown
            self.server.close()
            self.server.shutdown
            exit()


def main(argv):
    host = ''
    port = 4112

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

    bob = Bob(host, port)
    bob.run()


if __name__ == '__main__':
    main(sys.argv[1:])