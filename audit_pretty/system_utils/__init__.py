import signal
import pwd
import grp
from .syscall_table import syscall_table

signals = {}

audit_arch = {
    'c000003e': 'x86_64'
}


def init_signals_map():
    for name, signum in signal.Signals.__members__.items():
        signals[signum] = name
    signals[None] = '?'
    signals[0] = '?'


def decode_signal(signum) -> str:
    if len(signals) == 0:
        init_signals_map()
    return signals.get(signum, 'Unknown signal (' + str(signum) + ')')


def decode_syscall(callnum, arch='c000003e') -> str:
    try:
        return syscall_table[audit_arch[arch]][callnum]
    except KeyError:
        return 'Unknown syscall (' + str(callnum) + ')'


def decode_uid(uid, default=None):
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, TypeError):
        return default


def decode_gid(gid, default=None):
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, TypeError):
        return default


def decode_arch(arch, default=None):
    return audit_arch.get(arch, default)

