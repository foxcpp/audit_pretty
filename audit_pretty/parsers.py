import os
from collections import defaultdict
from audit_pretty.lowlevel_utils import decode_signal, decode_syscall
from audit_pretty.format_utils import format_helper
from datetime import datetime

# How to add support for new message type:
# 1. Implement pretty printer function. Call pretty_helper with
#    appropriate arguments. See AA pretty printer for good example.
# 2. Make sure you have fallback in case of some values is missing.
# 3. Implement main_info_filter. Throw out everything that may make
#    message unique. Again, See AA for good example.
# 4. Add functions to dicts.
# 5. Test!
#
# Note: '?' is special value and discarded by pretty_helper.

def apparmor_pretty(msg, suffix='') -> str:
    if msg['apparmor'] == 'DENIED' or msg['apparmor'] == 'ALLOWED':
        return format_helper(
                'AppArmor policy violation',
                timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
                urgency='warn',
                suffix=suffix,
                info={
                    'Operation': msg.get('operation'),
                    'Profile': msg.get('profile'),
                    'Target': msg.get('name', msg.get('peer')),
                    'Denied mask': msg.get('denied_mask')
                },
                extra_info={
                    'Requested mask': msg.get('requested_mask'),
                    'Process ID': msg.get('pid'),
                    'FS UID': msg.get('fsuid'),
                    'OUID': msg.get('ouid')
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


def seccomp_pretty(msg, suffix='') -> str:
    return format_helper(
            'seccomp policy violation',
            timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
            urgency='warn',
            suffix=suffix,
            info={
                'Executable': msg.get('exe', None),
                'Signal': decode_signal(msg['sig']) if msg['sig'] != 0 else None,
                'Errno': os.strerror(msg['code']) if msg['code'] != 0 else None,
                'System call': decode_syscall(msg['syscall'], msg['arch'])
            },
            extra_info={
                'User ID': msg.get('uid', '?'),
                'Group ID': msg.get('gid', '?'),
                'AUID': msg.get('auid', '?'),
                'PID': msg.get('pid', '?'),
                'Thread name': msg.get('comm', '?')
            }
    )


def seccomp_main_info(msg) -> dict:
    return {'type': 'SECCOMP', 'exe': msg['exe'], 'syscall': msg['syscall']}


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


pretty_printers: dict = defaultdict(lambda: default_pretty_printer,
    AVC=apparmor_pretty,
    SECCOMP=seccomp_pretty
)


main_info_filters: dict = defaultdict(lambda: default_info_filter,
    AVC=apparmor_main_info,
    SECCOMP=seccomp_main_info
)

