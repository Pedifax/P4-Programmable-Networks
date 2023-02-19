#!/usr/bin/env python3
import random
import socket
import sys
import string

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
from probe_hdrs import *


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv) < 2:
        print("Please pass 1 argument: <destination>")
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    pkt_list = []
    for i in range(1000):
        # generate message with different sizes
        message = f"{str(i)} " * random.randint(0, 99) + str(i)

        print("sending on interface %s to %s" % (iface, str(addr)))
        print(f"packet sid = {i}")

        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / Probe(sid=i) /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / message
        # pkt.show2()

        pkt_list.append(pkt)
    
    sendp(pkt_list, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
