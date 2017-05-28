import os
from Crypto import Random
from Crypto.PublicKey import RSA


def generate_key_pair():
    # Random number generator function.
    rng = Random.new().read

    # Generate RSA key object by providing PyCrypto with
    # desired key size and a randfunc.
    # See docs: https://www.dlitz.net/software/pycrypto
    # /doc/#crypto-publickey-public-key-algorithms
    key = RSA.generate(4096, rng)

    # Create and save the private key.
    f = open(os.path.join("../", 'master_bot_private_key.pem'), 'w')
    f.write(key.exportKey('PEM').decode('ascii'))
    f.close()

    # Create and save the public key in pastebin.net/publickeys/.
    f2 = open(os.path.join("pastebot.net", 'master_bot_public_key.pem'), 'w')
    f2.write(key.publickey().exportKey('PEM').decode('ascii'))
    f2.close()