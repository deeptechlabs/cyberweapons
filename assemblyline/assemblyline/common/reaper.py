import signal
import sys
import ctypes

libc = ctypes.CDLL("libc.so.6")


def set_death_signal(sig=signal.SIGTERM):
    if 'linux' not in sys.platform:
        return None

    def process_control():
        return libc.prctl(1, sig)
    return process_control
