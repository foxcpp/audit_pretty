from datetime import datetime
from audit_pretty.parser import default_pretty_printer, pretty_printer, main_info_filter
from audit_pretty.parser_utils import split_message
from audit_pretty.format_utils import format_helper


def generic_user_event(title, msg, suffix):
    pam_msg = split_message(msg['msg'], quotes='"')
    return format_helper(
        title=title,
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        suffix=suffix,
        info={
            'Account': pam_msg['acct'],
            'Command': pam_msg.get('exe'),
            'Session': msg.get('ses'),
            'Success': 'Yes' if pam_msg.get('res') == 'success' else 'No'
        },
        extra_info={
            'Process ID': msg.get('pid'),
            'Audit UID': msg.get('auid'),
            'Hostname': pam_msg.get('hostname') if pam_msg.get('hostname') != '?' else None,
            'Address': pam_msg.get('addr') if pam_msg.get('addr') != '?' else None,
            'Terminal': pam_msg.get('terminal') if pam_msg.get('terminal') != '?' else None
        })


@pretty_printer('USER_START')
def user_start(msg, suffix='') -> str:
    return generic_user_event('User session started', msg, suffix)


@pretty_printer('USER_LOGIN')
def user_login(msg, suffix='') -> str:
    return generic_user_event('User logged in', msg, suffix)


@pretty_printer('USER_END')
def user_end(msg, suffix='') -> str:
    return generic_user_event('User session ended', msg, suffix)


# TODO:
# @pretty_printer('USER_CMD')
# def user_cmd(msg, suffix) -> str:
#     pass


@pretty_printer('USER_ACCT')
def user_acct(msg, suffix='') -> str:
    return generic_user_event('User authorization', msg, suffix)


@pretty_printer('USER_AUTH')
def user_auth(msg, suffix='') -> str:
    return generic_user_event('User authentication', msg, suffix)


@main_info_filter('USER_START', 'USER_LOGIN', 'USER_END', 'USER_CMD', 'USER_ACCT', 'USER_AUTH')
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

