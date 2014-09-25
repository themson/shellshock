#!/usr/bin/env python
"""
Usage: sudo python dhcp_watch.py

This script monitors DHCP frames and highlights potentially malicious characters
contained withing DHCP reply options fields
"""

from __future__ import print_function, absolute_import, unicode_literals
from scapy.all import *
import signal
import sys
__author__ = 'themson mester'


INTERFACE = b'eth0'
BOOTREPLY = 2
BOLD_RED = '\033[1;91m'
END = '\033[0m'
WARNCHARS = set('@(){}')


def handler(signum, frame):
    print("\nInterrupt caught: shutting down")
    sys.exit(signum)


def print_frame(frame):
    if BOOTP in frame:
        if frame[BOOTP].op is BOOTREPLY:
            print("\nREPLY  : {}".format(frame.summary()))
            print("OPTIONS:")
            for option in frame['DHCP options'].options:
                warn = False
                if type(option) is tuple:
                    for arg in option:
                        if any(char in WARNCHARS for char in str(arg)):
                            warn = True
                if warn is True:
                    print(BOLD_RED + '        {}'.format(option) + END)
                else:
                    print('        {}'.format(option))

                if option == 'end':  # Skip padding
                    return
        else:
            print("\nREQUEST: {}".format(frame.summary()))


def sniffer():
    try:
        sniff(iface=INTERFACE, prn=print_frame, filter='udp and (port bootps or bootps)', store=0)
    except Exception as _e:
        print("ERROR - sniffer(): {}".format(_e.args))


def main():
    signal.signal(signal.SIGINT, handler)
    print("\nLaunching DHCP sniffer")
    print("Ctrl+C to exit")
    sniffer()


if __name__ == "__main__":
    main()
