import string


def is_hex(field):
    for ch in field:
        # We use this instead of string.hexdigits because only uppercase
        # letters is used in audit messages and we don't want to have a
        # false positive on 'aaf123'.
        if ch not in ['A', 'B', 'C', 'D', 'E', 'F'] and ch not in string.digits:
            return False
    return True


def decode_unsafe_hex(field, unsafe_formatter=lambda x: '') -> str:
    if not is_hex(field):
        return field
    try:
        # https://stackoverflow.com/a/9475354
        raw_chars = list(map(lambda x: int(x, base=16), [field[i:i+2] for i in range(0, len(field), 2)]))
        chars = []
        for char in raw_chars:
            if char < 32 or char > 126:
                chars += list(unsafe_formatter(char).encode('ascii'))
            else:
                chars.append(char)
        return ''.join(map(chr, chars))
    except (ValueError, UnicodeDecodeError):
        return field

