from collections import defaultdict
from datetime import datetime
from audit_pretty.format_utils import format_helper

# How to add support for new message type:
# 1. Implement pretty printer function. Call format_helper with
#    appropriate arguments. See AA pretty printer for good example.
# 2. Make sure you have fallback in case of some values is missing.
# 3. Implement main_info_filter. Throw out everything that may make
#    message unique. Again, See AA for good example.
# 4. Add @pretty_printer and @main_info_filter annotations.
# 5. Test!


def default_pretty_printer(msg, suffix='') -> str:
    return format_helper(
        'Unknown message type (type=' + msg['type'] + ')',
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='warn',
        suffix=suffix,
        info=dict(((k, v) for k, v in msg.items() if k not in {'time', 'type'})),
        extra_info={}
    )


def default_info_filter(msg) -> dict:
    m = msg.copy()

    def del_if_present(key):
        if key in m:
            del m[key]

    del_if_present('time')
    del_if_present('pid')
    del_if_present('fsuid')
    del_if_present('comm')
    return msg


pretty_printers: dict = defaultdict(lambda: default_pretty_printer)
main_info_filters: dict = defaultdict(lambda: default_info_filter)


def main_info_filter(*ids):
    def decorator(func):
        for id in ids:
            main_info_filters[id] = func
    return decorator


def pretty_printer(*ids):
    def decorator(func):
        for id in ids:
            pretty_printers[id] = func
    return decorator

