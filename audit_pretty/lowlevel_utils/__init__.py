import signal
from .syscall_table import syscall_table

signals = {}

seccomp_arch = { # Handle something other than x86_64.
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


def decode_syscall(callnum, scmp_arch='c000003e') -> str:
    try:
        return syscall_table[seccomp_arch[scmp_arch]][callnum]
    except KeyError:
        return 'Unknown syscall (' + str(callnum) + ')'

