#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR
from probe_hdrs import *

NUM_OF_PACKETS = 1000
global_inversions = 0

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]


def count_inversion(arrivals):
    global global_inversions

    for i in range(NUM_OF_PACKETS):
        for j in range(i+1, NUM_OF_PACKETS):
            if arrivals[i] > arrivals[j]:
                global_inversions += 1
    
    print("=" * 40)
    print(f"Number of global inversions: {global_inversions}")
    print("=" * 40)

    arrivals.clear()
    global_inversions = 0



def handle_pkt(pkt, arrivals):
    global NUM_OF_PACKETS

    if Probe in pkt and pkt[TCP].dport == 1234:
        sid = pkt[Probe].sid
        print(f"got a packet with sid = {sid}")
        sys.stdout.flush()

        arrivals.append(sid)
        if len(arrivals) == NUM_OF_PACKETS:
            count_inversion(arrivals)


def main():
    arrivals = []

    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x, arrivals))

if __name__ == '__main__':
    main()
