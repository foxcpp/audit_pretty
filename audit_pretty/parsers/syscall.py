from datetime import datetime
from os import strerror
from audit_pretty.parser import pretty_printer, main_info_filter
from audit_pretty.format_utils import format_helper
from audit_pretty.format_utils import unsafe_char_replacement as unsafe_format
from audit_pretty.field_sanitize import decode_unsafe_hex
import audit_pretty.system_utils as system_utils


@pretty_printer('SYSCALL', 1300)
def systemcall_pretty(msg, suffix=''):
    return format_helper(
        title='System call information',
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        suffix=suffix,
        info={
            'System call': system_utils.decode_syscall(msg['syscall']),
            'Result': ('ERROR: ' + strerror(-msg['exit'])) if msg['exit'] < 0 else msg['exit'],
            'Executable': decode_unsafe_hex(msg['exe'], unsafe_format),
            'Real UID/GID': '{} ({}) / {} ({})'.format(
                system_utils.decode_uid(msg['uid'], 'UNKNOWN'), msg['uid'],
                system_utils.decode_gid(msg['gid'], 'UNKNOWN'), msg['gid']),
            'Effective UID/GID': '{} ({}) / {} ({})'.format(
                system_utils.decode_uid(msg['euid'], 'UNKNOWN'), msg['euid'],
                system_utils.decode_gid(msg['egid'], 'UNKNOWN'), msg['egid']),
        },
        extra_info={
            'Argument 1': msg.get('a0'),
            'Argument 2': msg.get('a1'),
            'Argument 3': msg.get('a2'),
            'Argument 4': msg.get('a3'),
            'Argument 5': msg.get('a4'),
            'Argument 6': msg.get('a5'),
            'Filesystem UID/GID': '{} ({}) / {} ({})'.format(
                system_utils.decode_uid(msg.get('fsuid'), 'UNKNOWN'), msg.get('fsuid'),
                system_utils.decode_gid(msg.get('fsgid'), 'UNKNOWN'), msg.get('fsgid')),
            'Login UID': '{} ({})'.format(
                system_utils.decode_uid(msg.get('auid')), msg.get('auid')),
            'Process ID': msg.get('pid'),
            'Parent process ID': msg.get('ppid'),
            'Session ID': msg.get('ses'),
            'Terminal': msg.get('tty') if msg.get('tty') != '(none)' else None,
            'Thread name': decode_unsafe_hex(msg['comm'], unsafe_format) if 'comm' in msg else None,
            'Arch.': system_utils.decode_arch(msg['arch'], unsafe_format) if 'arch' in msg else None
        })


@main_info_filter('SYSCALL', 1300)
def systemcall_info_filter(msg):
    m = msg.copy()

    def rem(key):
        if key in m:
            del m[key]

    rem('time')
    rem('id')
    rem('a0')
    rem('a1')
    rem('a2')
    rem('a3')
    rem('a4')
    rem('a5')
    rem('suid')
    rem('sgid')
    rem('fsuid')
    rem('fsgid')
    rem('auid')
    rem('pid')
    rem('ppid')
    rem('ses')
    rem('tty')
    rem('comm')
    rem('arch')
    return m

