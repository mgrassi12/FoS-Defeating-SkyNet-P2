import os

from key import key_generator
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def sign_file(f):
    key = RSA.importKey(open('master_bot_private_key.pem', 'r').read())
    print(key)
    f_hashed = SHA256.new(f)
    signature = PKCS1_v1_5.new(key).sign(f_hashed)
    # print("signature is...")
    # print(signature)
    # print("f is...")
    # print(f)
    # print("f hashed is...")
    # print(f_hashed.digest())
    return signature + f

if __name__ == "__main__":

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
