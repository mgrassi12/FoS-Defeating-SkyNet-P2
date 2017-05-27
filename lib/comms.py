import struct
import datetime  # For 4. Preventing Replay.

from dh import create_dh_key, calculate_dh_secret  # For 1. Key Exchange.
from Crypto.Cipher import AES  # For 2. Confidentiality.
from . import crypto_utils  # For 2. Confidentiality.
from Crypto.Hash import HMAC  # For 3. Integrity.
from Crypto.Hash import SHA256  # For 3. Integrity.

timestamp_format = "%d-%m-%Y %H:%M:%S:%f"
timestamp_length = 26

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.block_size = 16  # bytes (128-bit).
        self.iv = None  # initialization variable for CBC.
        self.key = None  # key used in CBC.
        self.time_of_last_communication = None  # the last time this bot received a message.
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 
        self.time_of_last_communication = datetime.datetime.now()
        # Project code here...
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Default XOR algorithm can only take a key of length 32
        # (4 byte) and thus is very insecure and impractical. Also bits can be changed
        # easily with stream ciphers. Hence, we've changed to a block cipher (CBC).
        # We are using AES-256 (key is 32 byte string).

        self.iv = shared_hash[:16]  # from week 04 lecture, block size is 128-bits. Using first 16 bytes of shared_hash.
        self.key = shared_hash[32:]  # from week 04 lecture, key length up to 256-bits. Using last 32 bytes of shared_hash.
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        # Documentation on the arguments AES.new can handle:
        # www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html

    def send(self, data):
        if self.cipher:  # If a cipher exists on this bot...
            hmac = HMAC.new(((self.key).encode("ascii")), digestmod=SHA256)  # create a HMAC...
            data_with_hmac = bytes(hmac.hexdigest() + data.decode("ascii"), "ascii")  # and return a bytes
            # object with the data of the two.

            present_time = datetime.datetime.now()  # Get the current time...
            time_str = datetime.datetime.strftime(present_time, timestamp_format)  # format the time...
            data_with_hmac = bytes(time_str, 'ascii') + data_with_hmac  # and add it to the front of our
            # byte object containing the HMAC and data.

            # Pad all the aforementioned to ensure it is the size of 16 bytes...
            padded_data = crypto_utils.ANSI_X923_pad(data_with_hmac, self.block_size)
            encrypted_data = self.cipher.encrypt(padded_data)  # and encrypt it all.

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data  # Send without being encrypted; should only occur
            # at very beginning of each session.

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:  # If a cipher exists on this bot...
            padded_data = self.cipher.decrypt(encrypted_data)  # decrypt the received data...
            data = crypto_utils.ANSI_X923_unpad(padded_data, self.block_size)  # then unpad the data.

            timestamp = str(data[:timestamp_length], 'ascii')  # Unpack the timestamp...
            data = data[timestamp_length:]

            this_msg_timestamp = datetime.datetime.strptime(timestamp, timestamp_format)  # and check if...
            if this_msg_timestamp <= self.time_of_last_communication:  # this message's timestamp...
                print("Potential replay attack detected!")  # is suspicious...
                self.close()  # (and react to it)...
            else:
                print("Timestamp is good.")  # or not.

            self.time_of_last_communication = this_msg_timestamp  # Set the time of last communication to now.

            secret = (self.key).encode("ascii")  # Get the secret...
            hmac2 = HMAC.new(secret, digestmod=SHA256)  # to create a HMAC...
            hmac = data[:hmac2.digest_size * 2]  # and unpack the HMAC from the data...
            data = data[hmac2.digest_size * 2:]

            if hmac2.hexdigest() == str(hmac, "ascii"):  # to compare them.
                print ("HMAC matches!")
            else:
                print ("HMAC doesn't match! Panic!")
                self.close()

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
