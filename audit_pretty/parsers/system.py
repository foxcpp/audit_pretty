from datetime import datetime
from audit_pretty.parser import pretty_printer, main_info_filter
from audit_pretty.format_utils import format_helper
from audit_pretty.parser_utils import split_message
from audit_pretty.field_sanitize import decode_unsafe_hex
import audit_pretty.system_utils as system_utils


@pretty_printer('SERVICE_START', 1130)
def service_start(msg, suffix=''):
    systemd_msg = split_message(msg['msg'], quotes='"')
    return format_helper(
        title='Service start',
        suffix=suffix,
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        info={'Unit': systemd_msg['unit']})


@pretty_printer('SERVICE_STOP', 1131)
def service_stop(msg, suffix=''):
    systemd_msg = split_message(msg['msg'], quotes='"')
    return format_helper(
        title='Service stop',
        suffix=suffix,
        timestamp=datetime.fromtimestamp(msg['time']) if 'time' in msg else None,
        urgency='info',
        info={'Unit': systemd_msg['unit']})


@main_info_filter('SERVICE_START', 1130, 'SERVICE_STOP', 1131)
def main_info(msg):
    systemd_msg = split_message(msg['msg'], quotes='"')
    return {'msg': 'unit=' + systemd_msg['unit']}

