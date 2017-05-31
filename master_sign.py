import os

from key import key_generator
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def sign_file(f):
    # Creates a digital signature and appends it to the file.
    key = RSA.importKey(open('master_bot_private_key.pem', 'rb').read())  # Read the master bot's private key.
    f_hashed = SHA256.new(f)  # Get a fingerprint (hash) of the data to be sent.
    signature = PKCS1_v1_5.new(key).sign(f_hashed)  # Sign the fingerprint with the digital signature.
    return signature + f  # Package the signature with the file and return it.

if __name__ == "__main__":

    # If either the private or public key does not exist,
    # generate a new key pair.
    if not os.path.exists("master_bot_private_key.pem") or \
            not os.path.exists("master_bot_public_key.pem"):
        key_generator.generate_key_pair()

    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)

    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
