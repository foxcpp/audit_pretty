from collections import defaultdict
from audit_pretty.pretty_utils import pretty_helper

# How to add support for new message type:
# 1. 
#

def apparmor_pretty(msg, suffix='') -> str:
    if msg['apparmor'] == 'DENIED':
        return pretty_helper(
                'AppArmor policy violation',
                time_=msg.get('time', 0),
                urgency='warn',
                suffix=suffix,
                info={
                    'Operation': msg.get('operation', '?'),
                    'Profile': msg.get('profile', '?'),
                    'Target': msg.get('name', msg.get('peer', '?')),
                    'Denied mask': msg.get('denied_mask', '?')
                },
                extra_info={
                    'Requested mask': msg.get('requested_mask', '?'),
                    'Process ID': msg.get('pid', '?'),
                    'FS UID': msg.get('fsuid', '?'),
                    'OUID': msg.get('ouid', '?')
                })
    else:
        print('Unknown AppArmor message type, printing as is.')
        return default_pretty_printer(msg, suffix)


def apparmor_main_info(msg) -> dict:
    m = msg.copy()
    def del_if_present(key):
        if key in m:
            del m[key]
    if m['apparmor'] == 'DENIED':
        del m['time']
        del m['pid']
        del m['comm']
        # Don't present if event is not related to file system (ptrace comes to mind).
        del_if_present('fsuid')
        del_if_present('ouid')
    return m


def default_pretty_printer(msg, suffix='') -> str:
    return pretty_helper(
        'Unknown message type (type=' + msg['type'] + ')',
        time_=msg.get('time', 0),
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


pretty_printers: dict = defaultdict(lambda: default_pretty_printer,
    AVC=apparmor_pretty
)


main_info_filters: dict = defaultdict(lambda: default_info_filter,
    AVC=apparmor_main_info
)

