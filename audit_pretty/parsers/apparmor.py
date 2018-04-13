from datetime import datetime
from audit_pretty.parser import default_pretty_printer, pretty_printer, main_info_filter, subdict
from audit_pretty.format_utils import format_helper
from audit_pretty.field_sanitize import decode_unsafe_hex


def policy_violation(msg, suffix) -> str:
    return format_helper(
            'AppArmor policy violation',
            timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
            urgency='warn',
            suffix=suffix,
            info={
                'Operation': msg.get('operation'),
                'Profile': msg.get('profile'),
                'Target': decode_unsafe_hex(msg.get('name', msg.get('peer'))) if 'name' in msg or 'peer' in msg else None,
                'Denied mask': msg.get('denied_mask')
            },
            extra_info={
                'Requested mask': msg.get('requested_mask'),
                'Process ID': msg.get('pid'),
                'FS UID': msg.get('fsuid'),
                'OUID': msg.get('ouid'),
                'Thread name': decode_unsafe_hex(msg['comm']) if 'comm' in msg else None
            })


def status(msg, suffix) -> str:
    title = 'Unknown AppArmor operation (' + msg['operation'] + ')'
    if msg['operation'] == 'profile_load':
        title = 'AppArmor profile load'
    if msg['operation'] == 'profile_replace':
        title = 'AppArmor profile replace'
    if msg['operation'] == 'profile_unload':
        title = 'AppArmor profile unload'

    return format_helper(
            title=title,
            timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
            urgency='info',
            suffix=suffix,
            info={
                'Profile name': msg['name'],
            },
            extra_info={
                'Process ID': msg.get('pid'),
                'Process profile': msg.get('profile'),
                'Thread name': msg.get('comm')
            })


@pretty_printer('AVC', 1400)
def apparmor_pretty(msg, suffix='') -> str:
    if msg['apparmor'] == 'DENIED' or msg['apparmor'] == 'ALLOWED':
        return policy_violation(msg, suffix)
    elif msg['apparmor'] == 'STATUS':
        return status(msg, suffix)
    else:
        print('Unknown AppArmor message type, printing as is.')
        return default_pretty_printer(msg, suffix)


@main_info_filter('AVC', 1400)
def apparmor_main_info(msg) -> dict:
    if msg['apparmor'] == 'DENIED' or msg['apparmor'] == 'ALLOWED':
        return subdict(msg, ('type', 'apparmor', 'operation', 'profile', 'denied_mask', 'name', 'peer'))
    if msg['apparmor'] == 'STATUS':
        return subdict(msg, ('type', 'apparmor', 'operation', 'type', 'name'))

