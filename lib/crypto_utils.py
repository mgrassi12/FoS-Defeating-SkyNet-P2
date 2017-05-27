# ANSI X.923 pads the message with zeroes
# The last byte is the number of zeroes added
# This should be checked on unpadding
# Taken from tutorial in week 2
def ANSI_X923_pad(m, pad_length):
    # Work out how many bytes need to be added
    required_padding = pad_length - (len(m) % pad_length)
    # Use a bytearray so we can add to the end of m
    b = bytearray(m)
    # Then k-1 zero bytes, where k is the required padding
    b.extend(bytes("\x00" * (required_padding-1), "ascii"))
    # And finally adding the number of padding bytes added
    b.append(required_padding)
    return bytes(b)

def ANSI_X923_unpad(m, pad_length):
    # The last byte should represent the number of padding bytes added
    required_padding = m[-1]
    # Ensure that there are required_padding - 1 zero bytes
    if m.count(bytes([0]), -required_padding, -1) == required_padding - 1:
        return m[:-required_padding]
    else:
        # Raise an exception in the case of an invalid padding
        raise AssertionError("Padding was invalid")
