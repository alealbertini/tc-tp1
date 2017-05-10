#!/usr/bin/env python3
import argparse
from collections import namedtuple
from math import log2
import pydot
import scapy
from scapy.all import *
import sys
from tabulate import tabulate

# Constantes para filtrar paquetes relevantes:
ARP_ETHERTYPE = 0x806
WHO_HAS_OP = 1
IS_AT_OP = 2

# Definiendo la tupla Message: (IP fuente, IP destino).
# (Sobrecargamos el operador str para que se muestre mejor.)
class Message(namedtuple("MessageTuple", ["src", "dst"])):
        def __str__(self):
                return str("{:<16} \u2192 {:16}".format(self.src, self.dst))

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="archivo libpcap a analizar")
    parser.add_argument("-g",
                        help="exportar grafo de conversaciones (.pdf)",
                        dest="graph_output")
    parser.add_argument("-l", "--latex", help="imprimir en formato tabla de Latex",
                        dest="latex_format",
                        action="store_true")
    parser.add_argument("-c", "--csv",
                        help="Exportar csv para graficar",
                        dest="csv_output")
    parser.add_argument("-m", "--mensajes",
                        help="Mostrar tabla con tuplas(src, dst)",
                        dest="show_tuples",
                        action="store_true")

    return parser.parse_args()

def extractMessages(packets):
    ''' Extrae tuplas (fuente, destino) de la captura. '''
    messages = []
    for p in packets:
        if ARP not in p:
            continue
        if p.type == ARP_ETHERTYPE and p.op == WHO_HAS_OP:
            m = Message(p.psrc, p.pdst)
            messages.append(m)
    return messages

def messageCount(messages):
    ''' Cantidad de veces que aparece cada mensaje fuente->destino en la captura. '''
    count = dict()
    for m in messages:
        count[m] = count.get(m, 0) + 1
    return count

def extractIPs(packets):
    ''' Para los paquetes ARP de tipo who-has, devuelve dos listas:
    las IPs fuente y las IPs destino. '''
    src = []
    dst = []
    for p in packets:
        if ARP not in p:
            continue
        if p.type == ARP_ETHERTYPE and p.op == WHO_HAS_OP:
            src.append(p.psrc)
            dst.append(p.pdst)
    return src, dst

def numberOfPackets(ips):
    ''' Diccionario con la cantidad de veces que aparece la IP en la lista. '''
    count = dict()
    for ip in ips:
        count[ip] = count.get(ip, 0) + 1
    return count

def deduplicateIPs(ips):
    return set(ips)

def relativeFrequencies(ips):
    ''' Calcula la frecuencia relativa en base a los paquetes enviados O recibidos. '''
    total_items = len(ips)
    count = numberOfPackets(ips)
    freq = dict()
    for ip in count.keys():
        freq[ip] = count[ip] / total_items
    return freq

def packetsReceivedTable(packets_received):
    ''' Tabla de paquetes recibidos por ip. '''
    sorted_ips = sorted(packets_received, key=packets_received.get, reverse=True)
    table = []
    for ip in sorted_ips:
        table.append([ip, packets_received[ip]])

    print(tabulate(table,
                                 tablefmt="pipe",
                                 headers=["IP destino", "Cantidad de paquetes recibidos"],
                                 floatfmt=".4f"))

def relativeFrecuencyTable(relative_frequencies, entropy=None, format="pipe"):
    ''' Tabla con las frecuencias relativas (recibidos/todos o enviados/todos) de cada IP. '''
    table = []
    sorted_ips = sorted(relative_frequencies, key=relative_frequencies.get, reverse=True)
    for ip in sorted_ips:
        relative_frequency = relative_frequencies[ip]
        bit_information = bitInformation(relative_frequencies[ip])

        # Colorear valores menores a la entropía:
        if entropy is not None and bit_information <= entropy:
            bit_information = "\x1b[91m{:.4f}\x1b[0m".format(bit_information) # 91 == Light red

        table.append([ip, relative_frequency, bit_information])

    probability_sum = sum([relative_frequencies[ip] for ip in relative_frequencies.keys()])
    information_sum = sum([bitInformation(relative_frequencies[ip]) for ip in relative_frequencies.keys()])
    table.append(["Total", probability_sum, information_sum])

    if format == "latex":
        print(tabulate(table,
                                     tablefmt="latex",
                                     headers=["IP destino",
                                                        "Frecuencia relativa",
                                                        "Información [bits]"],
                                     floatfmt=".4f"))

    else:
        print(tabulate(table,
                                     tablefmt="pipe",
                                     headers=["\x1b[1mIP destino\x1b[0m",
                                                        "\x1b[1mFrecuencia relativa\x1b[0m",
                                                        "\x1b[1mInformación [bits]\x1b[0m"],
                                     floatfmt=".4f"))


def messagesRelativeFrequency(message_count, total_messages):
    ''' Calcular la frecuencia relativa de los mensajes enviados/recibidos por cada IP. '''
    freq = dict()
    for m in message_count.keys():
        freq[m] = message_count[m] / total_messages
    return freq

def sourceEntropy(relative_frequencies):
    ''' Entropía total de la fuente, tomando los símbolos como tuplas (fuente, destino). '''
    return sum([bitInformation(relative_frequencies[m]) * relative_frequencies[m]
                            for m in relative_frequencies.keys()])

def bitInformation(relative_frequency):
    ''' Dado p(s) la frecuencia relativa de un símbolo, devuelve la información que aporta en bits. '''
    if relative_frequency > 0:
        return -log2(relative_frequency)
    return 0


def generateConversationGraph(messages, output_file):
    graph = pydot.Dot(graph_type='digraph', size="8.7, 11.3", page="8.7, 11.3",
                      overlap="prism", concentrate="false")
    #, size="4x6", fontsize="20")
    for (source, destination) in messages:
        e = pydot.Edge(source, destination)
        graph.add_edge(e)

    graph.write(output_file, prog='twopi', format='pdf')

def gratuitousARPCount(messages):
    ''' Contar los Gratuitous ARP (Cumplen: src.ip == dst.ip). '''
    return sum([1 for m in messages if m[0] == m[1]])

def printCSV(source_relative_frequencies, destination_relative_frequencies, entropy, output):
    all_ips = set().union(source_relative_frequencies.keys(),
                                                destination_relative_frequencies.keys())
    output.write("IP,Enviados,Recibidos,Entropía={:.4f}\n".format(entropy))
    for ip in sorted(all_ips):
        sent = source_relative_frequencies.get(ip, 0)
        received = destination_relative_frequencies.get(ip, 0)
        sent_information = bitInformation(sent)
        received_information = bitInformation(received)
        output.write("{},{},{}\n".format(ip, sent_information, received_information))

def printCSVsent(source_relative_frequencies, destination_relative_frequencies, entropy, output):
    all_ips = set().union(source_relative_frequencies.keys(),
                                                destination_relative_frequencies.keys())
    output.write("IP,Enviados,Recibidos,Entropía={:.4f}\n".format(entropy))
    for ip in sorted(all_ips):
        sent = source_relative_frequencies.get(ip, 0)
        received = destination_relative_frequencies.get(ip, 0)
        sent_information = bitInformation(sent)
        received_information = bitInformation(received)
        if sent_information > 0 and sent_information <= entropy:
            output.write("{},{},{}\n".format(ip, sent_information, received_information))

def printCSVreceived(source_relative_frequencies, destination_relative_frequencies, entropy, output):
    all_ips = set().union(source_relative_frequencies.keys(),
                                                destination_relative_frequencies.keys())
    output.write("IP,Enviados,Recibidos,Entropía={:.4f}\n".format(entropy))
    for ip in sorted(all_ips):
        sent = source_relative_frequencies.get(ip, 0)
        received = destination_relative_frequencies.get(ip, 0)
        sent_information = bitInformation(sent)
        received_information = bitInformation(received)
        if received_information > 0 and received_information <= entropy:
            output.write("{},{},{}\n".format(ip, sent_information, received_information))



def main():
    args = getArguments()

    input_file = args.input
    print("Procesando {}...".format(input_file), end=' ')
    #packets = sniff(offline=input_file)
    packets = rdpcap(input_file)
    print("listo.")

    # Valores:
    total_packets = len(packets)
    print("Analizados", total_packets, "paquetes")

    # Extraer ips según en qué campo aparecen (fuente o destino):
    source_addresses, destination_addresses = extractIPs(packets)

    # Lista de IPs sin repetidos:
    source_addresses_no_rep = deduplicateIPs(source_addresses)
    destination_addresses_no_rep = deduplicateIPs(destination_addresses)
    print("\t * Aparecen {} IPs únicas como fuente".format(len(source_addresses_no_rep)))
    print("\t * Aparecen {} IPs únicas como destino".format(len(destination_addresses_no_rep)))

    # Extraer mensajes: tuplas(fuente, destino)
    messages = extractMessages(packets)
    message_count = messageCount(messages)
    unique_message_tuples = len(message_count)
    print("\t * Aparecen {} tuplas únicas (src, dst)".format(unique_message_tuples))

    packets_received = numberOfPackets(destination_addresses)
    print("\t * IP destino más popular: \x1b[1m{}\x1b[0m".format(max(packets_received, key=packets_received.get)))
    packets_sent = numberOfPackets(source_addresses)
    print("\t * IP fuente más popular: \x1b[1m{}\x1b[0m".format(max(packets_sent, key=packets_sent.get)))

    # Gratuitous ARPs:
    print("\t * Aparecen {} Gratuitous ARP".format(gratuitousARPCount(messages)))

    # Calcular frecuencias relativas:
    source_relative_frequencies = relativeFrequencies(source_addresses)
    destination_relative_frequencies = relativeFrequencies(destination_addresses)
    message_relative_frequencies = messagesRelativeFrequency(message_count, len(messages))

    # Entropía:
    entropy = sourceEntropy(message_relative_frequencies)
    print("\t * Entropia: \033[1;93mH(S) = {:.4f} bits\x1b[0m".format(entropy))

    table_format = "latex" if args.latex_format else "pipe"

    # Imprimir tablas:
    print()
    print("* Frecuencias relativas IP como fuente:")
    print(65*"-")
    relativeFrecuencyTable(source_relative_frequencies, entropy, table_format)
    print(65*"-")
    print()
    print("* Frecuencias relativas IP como destino:")
    print(65*"-")
    relativeFrecuencyTable(destination_relative_frequencies, entropy, table_format)
    print(65*"-")
    print()
    if args.show_tuples:
        print("* Frecuencias relativas tuplas:")
        print(65*"-")
        relativeFrecuencyTable(message_relative_frequencies, entropy, table_format)
        print(65*"-")

    if args.graph_output is not None:
        print("Exportando grafo de conversaciones en", args.graph_output)
        generateConversationGraph(message_count.keys(), args.graph_output)

    if args.csv_output is not None:
        output = open(args.csv_output, 'w') if args.csv_output else sys.stdout
        with open(args.csv_output, 'w') as output:
            printCSV(source_relative_frequencies, destination_relative_frequencies, entropy, output)

        # with open(args.csv_output + 's', 'w') as output:
        #     printCSVsent(source_relative_frequencies, destination_relative_frequencies, entropy, output)
        # with open(args.csv_output + 'r', 'w') as output:
        #     printCSVreceived(source_relative_frequencies, destination_relative_frequencies, entropy, output)
if __name__ == '__main__':
    main()
