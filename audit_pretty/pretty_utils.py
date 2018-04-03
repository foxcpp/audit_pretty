import time


global verbose
verbose = False

# ANSI escape sequences.
styling = {
    'bold': '\033[1m',
    'reset': '\033[0m'
}
urgency_styling = {
    'info': {'tcolor': ''},
    'warn': {'tcolor': '\033[38;5;11m'},
    'alert': {'tcolor': '\033[38;5;9m'},
}


def reset_styling():
    for k in styling.keys():
        styling[k] = ''
    for colors in urgency_styling.values():
        for color in colors.keys():
            colors[color] = ''


fmt = '''\
{bold}{timestamp}: {tcolor}{title}{reset} {suffix}
  {information}
'''
info_fmt = '{bold}{}:{reset} {}'


def pretty_helper(title: str, time_=0, info={}, extra_info={}, urgency='info', suffix='') -> str:
    return fmt.format(
        timestamp=(time.strftime('%D %H:%M:%S', time.localtime(time_)) if time_ != 0 else '??/??/?? ??:??:??'),
        title=title,
        suffix=suffix,
        information='\n  '.join([info_fmt.format(k, v, **styling) for k, v in info.items() if v != '?']) +
                    ('\n  ' + '\n  '.join([info_fmt.format(k, v, **styling) for k, v in extra_info.items()]) if verbose and v != '?' else ''),
        **styling, **urgency_styling[urgency]
    )
