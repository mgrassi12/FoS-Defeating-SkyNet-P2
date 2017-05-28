import os

from key import key_generator


def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    decoded_text = str(f, 'ascii')
    print(decoded_text)


if __name__ == "__main__":

    if not os.path.exists("master_bot_private_key.pem") or \
            not os.path.exists("pastebot.net/master_bot_public_key.pem"):
        key_generator.generate_key_pair()

    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
