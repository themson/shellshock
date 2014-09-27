#!/usr/bin/env python
"""
Usage: sudo python dhcp_mon.py

Monitor DHCP frames for potentially malicious characters within BOOTP and DHCP reply fields.
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
WARNING = b'*** MALICIOUS CHARACTER DETECTED ***'
BOLD_RED = '\033[1;91m'
END = '\033[0m'
frame_count = 0


def handler(signum, frame):
    """Gracefully catch sigint"""
    print("\n\nInterrupt Caught: shutting down")
    if frame_count > 0:
        print("PCAP File: {}".format(PCAP_LOG))
    print("Frames Logged: {}\n".format(frame_count))
    sys.exit(signum)


def log_frame(frame, logfile=PCAP_LOG):
    """Log frames containing warning chars to pcap file"""
    global frame_count
    frame_count += 1
    pcap_logger = PcapWriter(logfile, append=True)
    pcap_logger.write(frame)
    pcap_logger.close()


def parse_dhcp_opt(options):
    """Parse and print DHCP options

    parse for malicious chars
    highlight offending options
    :param options: frame[DHCP].options list
    :return char_found: bool
    """
    char_found = False
    print("        -  DHCP  -")
    for option in options:
        warn = False
        if type(option) is tuple:
            name = option[0]
            value = format(option[1])
            if any((char in WARNCHARS) for char in value):
                char_found, warn = True, True
            if warn is True:
                print(BOLD_RED + b'        {}: {}  {}'.format(name, value, WARNING) + END)
            else:
                print(b'        {}: {}'.format(name, value))
    return char_found


def parse_bootp_fields(bootp_fields):
    """Parse and print BOOTP fields

    parse for malicious chars
    highlight offending fields
    :param bootp_fields: <frame>[BOOTP].fields dictionary
    :return char_found: bool
    """
    char_found = False
    print("        -  BOOTP  -")
    for field_name in bootp_fields.keys():
        warn = False
        field_value = format(bootp_fields[field_name])
        if any((char in WARNCHARS) for char in field_value):
            char_found, warn = True, True
        if warn is True:
            print(BOLD_RED + b'        {}: {}    {}'.format(field_name, field_value, WARNING) + END)
        else:
            print(b'        {}: {}'.format(field_name, field_value))
    return char_found


def print_frame(frame):
    """Parse and print DHCP Frames

    parse sniffed DHCP frames
    print summary of client requests
    parse and print server replies
    log malicious frames
    :param frame:
    """
    if 'DHCP' in frame:
        bootp_fields = frame[BOOTP].fields
        dhcp_options = frame[DHCP].options
        type_value = dhcp_options[0][1]
        type_name = scapy.layers.dhcp.DHCPTypes[type_value]

        print("\n\nFRAME:  {}".format(frame.summary()))
        print("TYPE:   DHCP-{}".format(type_name))
        if type_value in DHCPSRVR_PACKETS:
            print("OPTIONS:")
            check_bootp, check_dhcp = parse_bootp_fields(bootp_fields), parse_dhcp_opt(dhcp_options)
            if check_bootp is True or check_dhcp is True:
                log_frame(frame)
                print("LOGGED: ./{}".format(PCAP_LOG))


def sniffer():
    """Instantiate scapy sniffer with DHCP filters"""
    try:
        sniff(iface=INTERFACE, prn=print_frame, filter='udp and (port bootps or bootps)', store=0)
    except Exception as _e:
        print("ERROR - sniffer(): {} {}".format(_e.args, _e.message))


def main():
    signal.signal(signal.SIGINT, handler)
    print("\nLaunching DHCP Monitor.")
    print("Logging Malicious Frames to: {}".format(PCAP_LOG))
    print("\n<Ctrl+C to exit>")
    sniffer()


if __name__ == "__main__":
    main()
