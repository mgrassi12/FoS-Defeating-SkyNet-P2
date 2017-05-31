import os

from key import key_generator
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


def decrypt_valuables(f):
    # Decrypt the contents of the file.
    key = RSA.importKey(open('master_bot_private_key.pem', 'rb').read())  # Read the master bot's private key.
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)  # Create the cipher the file was encrypted with
    # by giving PKCS1_OAEP the private key and hashing algorithm.
    plaintext = str(cipher.decrypt(f), 'ascii')  # Decrypt the data with this cipher.
    print(plaintext)


if __name__ == "__main__":

    # If either the private or public key does not exist,
    # generate a new key pair.
    if not os.path.exists("master_bot_private_key.pem") or \
            not os.path.exists("master_bot_public_key.pem"):
        key_generator.generate_key_pair()

    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
