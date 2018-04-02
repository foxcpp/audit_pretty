from audit_pretty.pretty_utils import pretty_helper

# How to add support for new message type:
# 1. 
#

def apparmor_pretty(msg, color=False, suffix='') -> str:
    if msg['apparmor'] == 'DENIED':
        return pretty_helper(
                'AppArmor policy violation',
                time_=msg.get('time', 0),
                urgency='warn',
                suffix=suffix,
                info={
                    'Operation': msg['operation'],
                    'Profile': msg['profile'],
                    'Target': msg['name'],
                    'Denied mask': msg['denied_mask']
                },
                extra_info={
                    'Requested mask': msg.get('requested_mask', '?'),
                    'Process ID': msg.get('pid', '?'),
                    'FS UID': msg.get('fsuid', '?'),
                    'OUID': msg.get('ouid', '?')
                })
    else:
        print('Unknown AppArmor message type, printing as is.')
        return None


def apparmor_main_info(msg) -> dict:
    m = msg.copy()
    if m['apparmor'] == 'DENIED':
        del m['time']
        del m['pid']
        del m['fsuid']
        del m['ouid']
        del m['comm']
    return m


pretty_printers: dict = {
    'AVC': apparmor_pretty
}


main_info_filters: dict = {
    'AVC': apparmor_main_info
}

