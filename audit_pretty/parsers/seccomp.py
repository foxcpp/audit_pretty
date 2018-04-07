from datetime import datetime
from audit_pretty.parser import pretty_printer, main_info_filter
from audit_pretty.system_utils import decode_signal, decode_syscall
from audit_pretty.format_utils import format_helper

@pretty_printer('SECCOMP', 1326)
def seccomp_pretty(msg, suffix='') -> str:
    return format_helper(
            'seccomp policy violation',
            timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
            urgency='warn',
            suffix=suffix,
            info={
                'Executable': msg.get('exe', None),
                'Signal': decode_signal(msg['sig']) if msg.get('sig', 0) != 0 else None,
                'Errno': os.strerror(msg['code']) if msg.get('code', 0) != 0 else None,
                'System call': decode_syscall(msg['syscall'], msg['arch'])
            },
            extra_info={
                'User ID': msg.get('uid'),
                'Group ID': msg.get('gid'),
                'AUID': msg.get('auid'),
                'PID': msg.get('pid'),
                'Thread name': msg.get('comm')
            }
    )


@main_info_filter('SECCOMP', 1326)
def seccomp_main_info(msg) -> dict:
    return {
        'type': 'SECCOMP',
        'exe': msg['exe'],
        'syscall': msg['syscall'],
        'arch': msg['arch']  # It's necessary to include arch otherwise system calls can be recognised incorrectly on different architectures.
    }

