#!/usr/bin/env python3

import argparse
import datetime
import os

def getArguments():
  parser = argparse.ArgumentParser()
  parser.add_argument("interface",
                      help="interfaz desde donde capturar")
  parser.add_argument("-p", "--path",
                      help="directorio en donde guardar la captura",
                      default=os.getcwd())
  parser.add_argument("-o", "--output",
                      help="Nombre del archivo de captura (default: \"captura-YYYY-MM-DDTHH:MM:SS.pcap\")",
                      default=nowISOFilename())
  parser.add_argument("-d", "--duracion",
                      help="dejar de capturar después de este tiempo [segundos]",
                      type=int)
  parser.add_argument("-a", "--arp", help="capturar sólo paquetes ARP",
                      action="store_true")

  return parser.parse_args()

def nowISOFilename():
  return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S") + ".pcap"

def normalizeFilename(f):
  ''' Agregar extensión .pcap si no la tiene. '''
  if f[-5:] != ".pcap":
    return f + ".pcap"
  return f

def main():
  args = getArguments()

  filename = normalizeFilename(args.output)
  output_path = os.path.join(args.path, filename)

  dumpcap_arguments = ["-i", args.interface,
                       "-P", # Guardar en formato libpcap
                       "-w", output_path]

  if args.arp:
    dumpcap_arguments.extend(["-f", "arp"])
  if args.duracion != None:
    dumpcap_arguments.extend(["-a", "duration:%d" % args.duracion])

  # Ejecutando dumpcap...
  os.execvp("dumpcap", dumpcap_arguments)

if __name__ == '__main__':
  main()