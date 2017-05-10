#!/usr/bin/env python3
import argparse
from math import log2
import scapy
from scapy.all import *
import sys
from tabulate import tabulate

def getArguments():
  parser = argparse.ArgumentParser()
  parser.add_argument("input",
                      help="archivo libpcap a analizar")
  parser.add_argument("-l", "--latex",
                      help="imprimir en formato LaTeX",
                      action="store_true")
  parser.add_argument("-c", "--csv",
                      help="imprimir en formato CSV",
                      action="store_true")
  parser.add_argument("-o", "--output",
                      help="guardar en archivo")

  return parser.parse_args()

def countBroadcasts(packets):
  return sum(1 for p in packets if p.dst == "ff:ff:ff:ff:ff:ff")

def printCSV(broadcasts, unicasts, p_broadcast, p_unicast, broadcast_info, unicast_info, entropy, output):
  output.write("Símbolo,Cantidad,Frec. Relativa,Info. [bits]\n")
  output.write("S_{{Broadcast}},{},{:.4f},{:.4f}\n".format(broadcasts, p_broadcast, broadcast_info))
  output.write("S_{{Unicast}},{},{:.4f},{:.4f}\n".format(unicasts, p_unicast, unicast_info))
  output.write("H(S),x,x,{:.4f}\n".format(entropy))

def printTable(broadcasts, unicasts, p_broadcast, p_unicast, broadcast_info, unicast_info, latex=False):
  table = [['Broadcasts', broadcasts, p_broadcast, broadcast_info],
           ["Unicast", unicasts, p_unicast, unicast_info],
           ["Total", broadcasts + unicasts, p_broadcast + p_unicast, broadcast_info + unicast_info]]

  table_format = ("latex" if latex else "pipe")

  print(tabulate(table, tablefmt=table_format,
                        headers=["Tipo", "Cantidad", "p", "Informacion"],
                        floatfmt=".4f"))

def main():
  args = getArguments()

  input_file = args.input
  print("Procesando %s..." % input_file)
  packets = sniff(offline=input_file)

  # Valores:
  total_packets = len(packets)
  broadcast_packets = countBroadcasts(packets)
  unicast_packets = total_packets - broadcast_packets
  p_broadcast = broadcast_packets / total_packets
  p_unicast = unicast_packets / total_packets
  broadcast_info = -log2(p_broadcast)
  unicast_info = -log2(p_unicast)
  entropy = p_broadcast * broadcast_info + p_unicast * unicast_info

  print('-' * 60)
  if args.csv:
    output = open(args.output, 'w') if args.output else sys.stdout
    printCSV(broadcast_packets, unicast_packets, p_broadcast, p_unicast,
             broadcast_info, unicast_info, entropy, output)
    if output is not sys.stdout:
      output.close()
  else:
    printTable(broadcast_packets, unicast_packets, p_broadcast, p_unicast,
               broadcast_info, unicast_info, args.latex)
  print('-' * 60)
  print("H(S) = %f" % entropy)

if __name__ == '__main__':
  main()
