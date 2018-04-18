from datetime import datetime
from audit_pretty.parser import pretty_printer, main_info_filter
from audit_pretty.format_utils import format_helper
from audit_pretty.field_sanitize import decode_unsafe_hex
import audit_pretty.system_utils as system_utils


@pretty_printer('PROCTITLE', 1327)
def proctitle(msg, suffix=''):
    return format_helper(
        title='Process title',
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        info={'Title': decode_unsafe_hex(msg['proctitle'])})


@pretty_printer('PATH', 1302)
def path(msg, suffix=''):
    return format_helper(
        title='Filesystem path',
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        info={
            'Path': decode_unsafe_hex(msg['name']),
            'Inode': msg['inode'],
        },
        extra_info={
            'Device (major:minor)': msg.get('dev'),
            'Owner UID': system_utils.decode_uid(msg.get('ouid'), str(msg.get('ouid'))) if 'ouid' in msg else None,
            'Owner GID': system_utils.decode_uid(msg.get('ogid'), str(msg.get('ogid'))) if 'ogid' in msg else None,
        })


@pretty_printer('CWD', 1307)
def cwd(msg, suffix=''):
    return format_helper(
        title='Current working directory',
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        info={
            'Path': decode_unsafe_hex(msg['cwd'])
        })

