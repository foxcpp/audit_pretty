from datetime import datetime
from audit_pretty.parser import default_pretty_printer, pretty_printer, main_info_filter
from audit_pretty.format_utils import format_helper


def generic_user_event(title, msg, suffix):
    return format_helper(
        title=title,
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        suffix=suffix,
        info={
            'Account': msg['acct'],
            'Command': msg.get('exe'),
            'Session': msg.get('ses'),
            'Success': 'Yes' if msg.get('res') == 'success\'' else 'No'
        },
        extra_info={
            'Process ID': msg.get('pid'),
            'Audit UID': msg.get('auid'),
            'Hostname': msg.get('hostname') if msg.get('hostname') != '?' else None,
            'Address': msg.get('addr') if msg.get('addr') != '?' else None,
            'Terminal': msg.get('terminal') if msg.get('terminal') != '?' else None
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

    def rem(key):
        if key in m:
            del m[key]

    rem('time')
    rem('msg')
    rem('hostname')
    rem('addr')
    rem('pid')
    rem('uid')
    rem('auid')
    rem('ses')
    rem('exe')
    rem('terminal')
    return m

