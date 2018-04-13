from datetime import datetime
from audit_pretty.parser import default_pretty_printer, pretty_printer, main_info_filter
from audit_pretty.parser_utils import split_message
from audit_pretty.format_utils import format_helper
from audit_pretty.field_sanitize import decode_unsafe_hex
from audit_pretty.system_utils import decode_uid


def generic_user_event(title, msg, suffix):
    pam_msg = split_message(msg['msg'], quotes='"')
    return format_helper(
        title=title,
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        suffix=suffix,
        info={
            'Account': pam_msg.get('acct'),
            'Command': pam_msg.get('exe', pam_msg.get('cmd')),
            'Session': msg.get('ses'),
            'Success': 'Yes' if pam_msg.get('res') == 'success' else 'No'
        },
        extra_info={
            'Process ID': msg.get('pid'),
            'Audit UID': decode_uid(msg.get('auid')) if 'auid' in msg else None,
            'Hostname': pam_msg.get('hostname') if pam_msg.get('hostname') != '?' else None,
            'Address': pam_msg.get('addr') if pam_msg.get('addr') != '?' else None,
            'Terminal': pam_msg.get('terminal') if pam_msg.get('terminal') != '?' else None
        })


@pretty_printer('USER_START', 1105)
def user_start(msg, suffix='') -> str:
    return generic_user_event('User session started', msg, suffix)


@pretty_printer('USER_LOGIN', 1112)
def user_login(msg, suffix='') -> str:
    return generic_user_event('User logged in', msg, suffix)


@pretty_printer('USER_END', 1106)
def user_end(msg, suffix='') -> str:
    return generic_user_event('User session ended', msg, suffix)


@pretty_printer('USER_CMD', 1123)
def user_cmd(msg, suffix) -> str:
    pam_msg = split_message(msg['msg'], quotes='"')
    return format_helper(
        title='Command executed with different user\'s priveleges',
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        suffix=suffix,
        info={
            'Executor\'s UID': decode_uid(msg['auid'], default='UNKNOWN-USER') + ' (' + str(msg['auid']) + ')',
            'Working directory': pam_msg['cwd'],
            'Command': decode_unsafe_hex(str(pam_msg['cmd'])),
            'Session': msg.get('ses'),
            'Success': 'Yes' if pam_msg.get('res') == 'success' else 'No'
        },
        extra_info={
            'Process ID': msg.get('pid'),
            'Hostname': pam_msg.get('hostname') if pam_msg.get('hostname') != '?' else None,
            'Address': pam_msg.get('addr') if pam_msg.get('addr') != '?' else None,
            'Terminal': pam_msg.get('terminal') if pam_msg.get('terminal') != '?' else None
        })


@pretty_printer('USER_ACCT', 1101)
def user_acct(msg, suffix='') -> str:
    return generic_user_event('User authorization', msg, suffix)


@pretty_printer('USER_AUTH', 1100)
def user_auth(msg, suffix='') -> str:
    return generic_user_event('User authentication', msg, suffix)


@main_info_filter('USER_START', 1105, 'USER_LOGIN', 1112, 'USER_END', 1106,
                  'USER_CMD', 1123, 'USER_ACCT', 1101, 'USER_AUTH', 1100)
def user_main_info(msg):
    m = msg.copy()
    pam = split_message(m['msg'], quotes='"')

    def rem(d, key):
        if key in d:
            del d[key]


    rem(m, 'id')
    rem(m, 'time')
    rem(m, 'msg')
    rem(pam, 'hostname')
    rem(pam, 'addr')
    rem(m, 'pid')
    rem(m, 'uid')
    rem(m, 'auid')
    rem(m, 'ses')
    rem(pam, 'cwd')
    rem(pam, 'op')
    rem(pam, 'exe')
    rem(pam, 'terminal')

    m['msg'] = ' '.join(['{}="{}"'.format(k, v) for k, v in pam.items()])
    return m

