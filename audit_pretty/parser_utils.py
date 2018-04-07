import re
from collections import defaultdict

type_quotes = defaultdict(lambda: "'", {
    'AVC': '"',
    '1400': '"',
})



def split_message(msg, quotes="'") -> dict:
    split_regexp = r'([a-zA-Z\-\_]+)=(?:[' + quotes + r'](.+?)[' + quotes + ']|([^ ]+))'
    # audit message is a sequence of values in form key="value" or key='value' or key=value.
    # Value can contain whitespace so we can't just line.split().split('=').
    result = {}
    for match in re.finditer(split_regexp, msg):
        if match.group(2) is not None:
            result[match.group(1)] = match.group(2)
        if match.group(3) is not None:
            result[match.group(1)] = match.group(3)
    for k, v in result.items():
        try:
            if v.isdigit():
                result[k] = int(v)
            if v.startswith('0x'):
                result[k] = int(v, base=16)
        except ValueError:
            pass
    return result


def parse_message(line: str) -> dict:
    trimmed = line.strip()
    if len(trimmed) == 0 or 'audit' not in trimmed:
        return None
    if trimmed.startswith('['):
        # Reading from dmesg, strip timestamp and 'audit:' prefix.
        trimmed = re.sub(r'^\[\d+\.\d+\] audit: ', '', trimmed)
    match = re.fullmatch(r'type=([0-9_A-Z]+) (?:msg=)?audit\((\d+)\.\d+:(\d+)\): (.+)', trimmed)
    if match is None:
        return None
    msg = 'type={} time={} id={} {}'.format(*match.group(1, 2, 3, 4))
    return split_message(msg, type_quotes[match.group(1)])

