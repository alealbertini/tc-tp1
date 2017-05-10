# tc-tp1
Redes TP1: Wiretapping

## Dependencias
	* python3
	* scapy
	* pydot
	* tabulate
## Instrucciones de uso
`main.py` invoca a `analizarARP.py` y a `analizarBroadcast.py` según el experimento a realizar. Recibe un archivo libpcap como entrada.

```
usage: main.py [-h] [-a] [-b] input

positional arguments:
  input            archivo libpcap a analizar

optional arguments:
  -h, --help       show this help message and exit
  -a, --arp        Analizar S1 (ej. 2): paquetes ARP
  -b, --broadcast  Analizar S (ej. 1): paquetes unicast vs. broadcast

```

Ejemplo: `./main.py --broadcast ../capturas/captura-ej1.pcap`