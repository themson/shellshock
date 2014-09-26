#!/usr/bin/env python
"""
Usage: sudo python dhcp_mon.py

Monitor DHCP frames for potentially malicious characters within reply options fields. 
Warn to stdout, log offending frames to PCAP_LOG
"""

from __future__ import print_function, absolute_import, unicode_literals
from scapy.all import *
import signal
import sys
import time
__author__ = 'themson mester'


WARNCHARS = set('(){}')  # Chars to Check
INTERFACE = b'eth0'  # Interface to sniff
PCAP_LOG = b'dhcp-mon-' + time.strftime('%m.%d.%y-%Hh%Mm%Ss') + '.pcap'
DHCPSRVR_PACKETS = (2, 5)
BOLD_RED = '\033[1;91m'
END = '\033[0m'


def handler(signum, frame):
    """Gracefully catch sigint"""
    print("\nInterrupt caught: shutting down")
    sys.exit(signum)


def log_frame(frame, logfile=PCAP_LOG):
    """Log packets containing warning chars to pcap file"""
    pcap_logger = PcapWriter(logfile, append=True)
    pcap_logger.write(frame)
    pcap_logger.close()  # flushed on close


def print_frame(frame):
    """Parse and print DHCP Frames

    parse sniffed DHCP frames
    print summary of client requests
    print full options of server replies
    Highlight potentially malicious chars

    :param frame:
    """
    if 'DHCP' in frame:
        options = frame['DHCP options'].options
        type_value = options[0][1]
        type_name = scapy.layers.dhcp.DHCPTypes[type_value]
        print("\nFRAME: {}".format(frame.summary()))
        print("TYPE:  DHCP-{}".format(type_name))

        if type_value in DHCPSRVR_PACKETS:
            print("OPTIONS:")
            for option in options:
                warn = False
                if type(option) is tuple:
                    for arg in option:  # malicious char check
                        if any(char in WARNCHARS for char in str(arg)):
                            warn = True
                if warn is True:
                    print(BOLD_RED + '        {} *** MALICIOUS CHARACTER DETECTED *** Logging to: ./{}'
                          .format(option, PCAP_LOG) + END)
                    log_frame(frame)
                else:
                    print('        {}'.format(option))
                if option == 'end':  # Skip padding
                    return


def sniffer():
    """Instantiate scapy sniffer with DHCP filters"""
    try:
        sniff(iface=INTERFACE, prn=print_frame, filter='udp and (port bootps or bootps)', store=0)
    except Exception as _e:
        print("ERROR - sniffer(): {}".format(_e.args))


def main():
    signal.signal(signal.SIGINT, handler)
    print("\nLaunching DHCP monitor.")
    print("Ctrl+C to exit")
    sniffer()


if __name__ == "__main__":
    main()
