#! /usr/bin/env python
import sys
from scapy.all import *

if __name__ == "__main__":
	tiempo = int(sys.argv[1])
	p = sniff(iface = conf.iface, timeout = tiempo, prn = lambda x:x.summary())
	wrpcap("captura.pcap", p)
