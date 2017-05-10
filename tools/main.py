#!/usr/bin/env python3
import argparse
import os

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("input",
                        help="archivo libpcap a analizar")
    parser.add_argument("-a", "--arp",
                        help="Analizar S1 (ej. 2): paquetes ARP",
                        action="store_true")
    parser.add_argument("-b", "--broadcast",
                        help="Analizar S (ej. 1): paquetes unicast vs. broadcast",
                        action="store_true")
    return parser.parse_args()

def main():
    args = getArguments()
    input_filename = os.path.basename(args.input)

    print("input:", args.input)
    if args.arp: # Ej. 2
        print("Analizando S1")
        results_directory = "../resultados/ej2"
        csv_output = "{}/{}.csv".format(results_directory, input_filename)
        graph_output = "{}/{}.pdf".format(results_directory, input_filename)
        os.system("./analizarARP.py {} -c {} -g {}".format(args.input, csv_output, graph_output))

        sent_graphic_filename = "{}/{}-enviados.pdf".format(results_directory, input_filename)
        received_graphic_filename = "{}/{}-recibidos.pdf".format(results_directory, input_filename)

        print("Guardando gráfico en", sent_graphic_filename)
        os.system("gnuplot -c {} {} {}".format("{}/packets-sent.plot".format(results_directory),
                                                csv_output,
                                                sent_graphic_filename))

        print("Guardando gráfico en", received_graphic_filename)
        os.system("gnuplot -c {} {} {}".format("{}/packets-received.plot".format(results_directory),
                                                csv_output,
                                                received_graphic_filename))

    if args.broadcast: # Ej. 1
        print("Analizando S")
        os.system("./analizarBroadcast.py {}".format(args.input))

if __name__ == "__main__":
    main()

