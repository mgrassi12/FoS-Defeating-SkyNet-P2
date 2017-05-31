from Crypto import Random
from Crypto.PublicKey import RSA


def generate_key_pair():
    # Random number generator function.
    rng = Random.new().read

    # Generate a RSA key object by providing PyCrypto with
    # desired key size and a randfunc.
    # See docs: https://www.dlitz.net/software/pycrypto
    # /doc/#crypto-publickey-public-key-algorithms
    key = RSA.generate(4096, rng)

    # Create and save the private key in the project folder.
    # In practice, the private key would be stored locally with
    # the master bot and would not be accessible by anyone else.
    # However, this is irrelevant for our botnet simulation as everything is local.
    f = open('master_bot_private_key.pem', 'wb')
    f.write(key.exportKey('PEM').decode('ascii'))
    f.close()

    # Create and save the public key in the project folder.
    # In practice, the public key would be accessible from
    # the public server (in this case, the hypothetical pastebot.net).
    # However, this is irrelevant for our botnet simulation as everything is local.
    f = open('master_bot_public_key.pem', 'wb')
    f.write(key.publickey().exportKey('PEM').decode('ascii'))
    f.close()
