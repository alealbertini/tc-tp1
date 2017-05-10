#! /usr/bin/env python
import sys
from scapy.all import *

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <interface> <segundos>"
    else:
        interface = ""
        tiempo = int(sys.argv[2])
        p = sniff(iface = conf.iface, timeout = tiempo, prn = lambda x:x.summary())
        wrpcap("captura.pcap", p)
