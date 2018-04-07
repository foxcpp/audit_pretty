import datetime
from functools import partial

global verbose
verbose = False

# ANSI escape sequences.
# https://stackoverflow.com/a/33206814
styling = {
    'red': '\033[38;5;9m',
    'bold': '\033[1m',
    'reset': '\033[0m'
}

msg_fmt = partial('''\
{bold}{timestamp}: {title}{reset} {suffix}
{information}
'''.format, **styling)
field_fmt = partial('{bold}{}:{reset} {}'.format, **styling)


def dsum(a: dict, b: dict) -> dict:
    c = a.copy()
    c.update(b)
    return c


def unsafe_char_replacement(ch: int) -> str:
    if ch == ord('\n'):
        return styling['red'] + r'\n' + styling['reset']
    if ch == ord('\t'):
        return styling['red'] + r'\t' + styling['reset']
    return styling['red'] + '%' + hex(ch) + styling['reset']


def format_helper(title: str, timestamp=None, info={}, extra_info={}, urgency='info', suffix='') -> str:
    if not verbose:
        extra_info = {}
    return msg_fmt(
        timestamp=timestamp if timestamp is not None else '????-??-?? ??:??:??',
        title=title,
        suffix=suffix,
        information='\n'.join(map(lambda x: '  ' + field_fmt(*x), filter(lambda x: x[1] is not None, dsum(info, extra_info).items())))
    )

