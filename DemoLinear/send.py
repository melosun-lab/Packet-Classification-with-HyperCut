#!/usr/bin/env python

import argparse
import socket

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP

from time import sleep


def get_if():
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p", help="Protocol name To send TCP/UDP etc packets", type=str)
    parser.add_argument("--src", help="IP address of the source", type=str)
    parser.add_argument("--des", help="IP address of the destination", type=str)
    parser.add_argument("--m", help="Raw Message", type=str)
    #parser.add_argument("--dur", help="in seconds", type=str)
    parser.add_argument("--sp", help="TCP/UDP source port",type=int)
    parser.add_argument("--dp", help="TCP/UDP destination port",type=int)
    args = parser.parse_args()

    if args.p and args.src and args.des and args.m and args.sp and args.dp:
        addr = socket.gethostbyname(args.des)
        iface = get_if()
        if args.p == 'UDP':
            pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(src=args.src,dst=addr, tos=1) / UDP(dport=args.dp, sport=args.sp) / args.m
            pkt.show2()
            try:
                sendp(pkt, iface=iface)
                sleep(1)
            except KeyboardInterrupt:
                raise
        elif args.p == 'TCP':
            pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(src=args.src,dst=addr, tos=1) / TCP(dport=args.dp, sport=args.sp)/ args.m
            pkt.show2()
            try:
                sendp(pkt, iface=iface)
                sleep(1)
            except KeyboardInterrupt:
                raise


if __name__ == '__main__':
    main()
