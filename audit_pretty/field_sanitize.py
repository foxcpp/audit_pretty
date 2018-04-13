import string
import binascii

from audit_pretty.format_utils import unsafe_char_replacement


def is_hex(field):
    for ch in field:
        # We use this instead of string.hexdigits because only uppercase
        # letters is used in audit messages and we don't want to have a
        # false positive on 'aaf123'.
        if ch not in ['A', 'B', 'C', 'D', 'E', 'F'] and ch not in string.digits:
            return False
    return True


def decode_unsafe_hex(field, unsafe_formatter=unsafe_char_replacement) -> str:
    if not is_hex(field):
        return field
    try:
        raw_chars = binascii.unhexlify(field)
        chars = bytearray()
        for char in raw_chars:
            if char < 32 or char > 126:
                chars += unsafe_formatter(char).encode('ascii')
            else:
                chars.append(char)
        return chars.decode()
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return field

