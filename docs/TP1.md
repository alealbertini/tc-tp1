Title:  TP1: Wiretapping
Author: Abel Delgadillo
        Martín Monti
        Santiago Gil
Date:   2do Cuatrimestre de 2016
Abstract: En este trabajo práctico buscamos analizar diversos aspectos de distintas redes de computadoras utilizando las herramientas analíticas de la teoría de la información. Para eso realizaremos observaciones a través de la captura de paquetes en distintas las redes, de los cuales buscaremos extraer información que nos permita caracterizar diversos aspectos de las mismas.


# Primera parte
En esta parte vamos a capturar paquetes en un enlace y luego analizaremos $S$, una fuente de información binaria de memoria nula. La misma se caracteriza por producir dos símbolos definidos de la siguiente manera:

i. **$S_\text{broadcast}$**: el campo `fuente` del paquete capturado es `ff:ff:ff:ff:ff:ff`, y
ii. **$S_\text{unicast}$**: el campo `destino` del paquete es distinto.

Los paquetes *unicast* en la red son aquellos que están destinados a un único destinatario (el campo `destino` contiene la *dirección MAC* de 48 bits que identifica unívocamente a dicho destinatario). Por el otro lado, los *broadcast* son aquellos que son enviados con la intención de que sean recibidos por todos los dispositivos en un mismo dominio de la red.

Para realizar las captura, utilizamos la herramienta `dumpcap`[^dumpcap], que permite capturar los datos de una interfaz de red y guardarlos en un archivo con formato `libpcap`.

Para simplificar las operaciones de captura, implementamos un script en Python (`capturar.py`) que facilita invocar a `dumpcap` con los parámetros necesarios.

Para procesar los datos del archivo de captura producido por el proceso anterior, implementamos otra herramienta en Python (`analizar.py`), que utiliza la biblioteca `Scapy`. La misma lee un archivo `libpcap`, cuenta la cantidad de paquetes de cada tipo y devuelve los siguientes valores: frecuencia relativa de la ocurrencia de cada símbolo: $p(s)$; la información en bits aportada de cada símbolo: $I(s)$; y la entropía de la fuente: $H(S)$.

A lo largo de este informe, vamos a interpretar las cantidades de información en *bits*, es decir, vamos a usar logaritmos en base 2 para realizar los cálculos. Si asumimos que cada símbolo $s$ de la fuente $S$ es equiprobable, es decir que $p(s) = 1/|S| = 1/2$, entonces la entropía máxima de $S$ será $H_{\text{máx}}(S) = \log_2(p(s)) = \log_2(1/2) = 1$ bit.

[^dumpcap]: Incluida con `Wireshark`. [https://wireshark.org/docs/man-pages/dumpcap.html](https://wireshark.org/docs/man-pages/dumpcap.html)

## Red 1: Red hogareña
Analizaremos los resultados observados al realizar una captura de 1 hora de duración en una red doméstica con 15 dispositivos conectados. La captura fue realizada a través de una interfaz inalámbrica, por lo que todos los paquetes en el aire fueron capturados. Es importante hacer esa distinción, ya que en caso de realizar la captura a través de una interfaz Ethernet conectada a la red mediante un switch no veríamos aquellos paquetes que no son destinados al host donde esta corriendo la herramienta de captura---pues el switch se encarga de optimizar el tráfico evitando enviar paquetes a donde no son necesarios. En ese caso, sin embargo, veríamos todos los paquetes broadcast.

### Resultados
La Tabla \ref{red1:infot} muestra los resultados de la captura. Observamos que el símbolo $S_\text{unicast}$ tuvo más apariciones en la captura: casi el 64% de los paquetes. En consecuencia, al ser más probables de observar, la información aportada es menor que la del símbolo $S_\text{broadcast}$, que es más predecible.

\begin{table}
\caption{Apariciones de cada símbolo en la captura realizada para la fuente $S$ en la red 1.}
\label{red1:infot}
\begin{tabular}{|l|r|r|r|}
\hline
\textbf{Símbolo}       &  \textbf{Cantidad} &  \textbf{Frec. Relativa} &   \textbf{Info. [bits]} \\
\hline
$S_\text{broadcast}$  &  763  & 0,3621  & 1,4654 \\
$S_\text{unicast}$    &   1344 & 0,6379  & 0,6487 \\
\hline
\hline
Total      & 2107 & 1,0000 & 2,1141 \\
\hline
\end{tabular}
\end{table}

La Figura \ref{red1:info} refleja la relación entre la información aportada por ambos símbolos y la entropía de la fuente, cuyo valor observado es $H(S_1) = 0.9444$ bits.

\begin{figure}
\includegraphics[width=\linewidth]{graficos/red1-info}
\caption{Información aportada por cada símbolo y entropía de la red 1}
\label{red1:info}
\end{figure}

Un dato importante es que, de todos los paquetes capturados, los paquetes del protocolo ARP formaron parte del 10,8% de todos los paquetes de la red. Como describiremos en detalle la siguiente sección, los mensajes del protocolo ARP consisten de una pregunta broadcast y una respuesta unicast.

Por la naturaleza de las redes basadas en switches, las respuestas podrían no ser vistas desde el dispositivo de captura, por lo que las frecuencias relativas podrían no ser 100% exactas con lo que ocurre en la realidad. En consecuencia, tampoco sería exacta la entropía que calculamos. Es decir, los mensajes impuestos por algunos protocolos de bajo nivel de la red (otro ejemplo es DHCP, con 1,3\% de los paquetes) que utilizan los mensajes broadast como punto fundamental para lograr la coordinación entre hosts que de otra forma podrían ser desconocidos podría estar influenciando la entropía de la fuente $S$, favoreciendo la probabilidad de observar un mensaje de tipo broadcast.

## Red 2: Laboratorios DC
Se capturaron 19236 paquetes en los laboratorios de la Facultad, en un instante en el cual se observaron más de 280 dispositivos conectados. La captura se realizó a través de un *access point* inalámbrico.

### Resultados
La entropía calculada a partir de las observaciones es de $H(S) = 0.7495$ bits

La Tabla \ref{ej2:infot} muestra los resultados de la captura. Observamos que el símbolo $S_\text{unicast}$ tuvo más apariciones en la captura, casi el 79% de los paquetes. En consecuencia, al ser más probables de observar, la información aportada es menor que la del símbolo $S_\text{broadcast}$, que es más predecible.

La Figura \ref{red2:info} refleja la relación entre la información aportada por ambos símbolos y la entropía de la fuente.

\begin{table}
\caption{Apariciones de cada símbolo en la captura realizada para la fuente $S$ en la red 2.}
\label{ej2:infot}
\begin{tabular}{|l|r|r|r|}
\hline
Tipo       &  Cantidad & p & Informacion \\
\hline
Broadcasts &  4121 & 0.2142 & 2.2227 \\
Unicast    &  15115 & 0.7858 & 0.3478 \\
\hline
\hline
Total      &  19236 & 1.0000 & 2.5706 \\
\hline
\end{tabular}
\end{table}

\begin{figure}
\includegraphics[width=\linewidth]{graficos/labos-info}
\caption{Información aportada por cada símbolo y entropía de la red 2}
\label{red2:info}
\end{figure}

En esta captura, los paquetes del protocolo ARP formaron parte del 12,4% de todos los paquetes de la red.

De nuevo debemos tener en cuenta la influencia que tienen tanto los protocolos de bajo nivel de la red (ARP, entre otros) y el método de captura, los cuales hacen más probable la observación de paquetes de tipo broadcast.

## Red 3: Hotspot Wi-Fi abierto de un centro comercial
Se capturaron 19660 paquetes en una red abierta en un local de la cafetería Starbucks. En el instante de la captura se observaron 86 direcciones MAC únicas de dispositivos conectados a la red.

### Resultados
La entropía calculada a partir de la captura es $H(S) = 0.114229$ bits.

La Tabla \ref{red3:infot} muestra los resultados de la captura, donde se puede observar cómo los paquetes unicast fueron varios órdenes de magnitud más frecuentes, aportando menor información y reduciendo considerablemente la entropía de la fuente.

\begin{table}
\caption{Apariciones de cada símbolo en la captura realizada para la fuente $S$ en la red 3.}
\label{red3:infot}
\begin{tabular}{|l|r|r|r|}
\hline
Tipo       &   Cantidad & p & Info. [bits] \\
\hline
Broadcasts &        301 & 0.0153 & 6.0294 \\
Unicast    &      19359 & 0.9847 & 0.0223 \\
\hline
\hline
Total      &      19660 & 1.0000 & 6.0516 \\
\hline
\end{tabular}
\end{table}


\begin{figure}
\includegraphics[width=\linewidth]{graficos/red3-info}
\caption{Información aportada por cada símbolo y entropía de la red 3}
\label{red2:info}
\end{figure}

En esta captura, los paquetes relacionados con el protocolo ARP representaron menos del 1% del tráfico capturado.

## Conclusiones
Vimos que a medida que la cantidad de hosts en una red creció, creció la diferencia entre paquetes unicast (que aparecieron cada vez con más frecuencia) y los paquetes broadcast (que cada vez fueron menos con respecto a los unicast).

En todos los casos, las frecuencias relativas de los símbolos $S_\text{unicast}$ y $S_\text{broadcast}$ estuvieron lejos de ser equiprobables. Es decir, que las entropías de las distintas capturas de la fuente $S$ no alcanzaron sus posibles valores máximos. Además, las diferencias absolutas entre esos valores de probabilidad fueron variando de distintas formas en las distintas redes que observamos.


----------

\newpage
# Segunda parte
En esta parte vamos a capturar paquetes **ARP** en distintas redes, a partir de lo cual vamos a intentar conocer más sobre la red y a determinar cuáles son los nodos *distinguidos* que se comunican dentro de la misma.

## ARP (*Address Resolution Protocol*)
ARP es un protocolo de la capa de enlace que permite realizar una asociación entre direcciones de la capa de enlace (en el caso de Ethernet, *MAC addresses*) y direcciones de la capa de transporte: direcciones del protocolo IP.

El inconveniente que resuelve este protocolo es el que aparece cuando un host determinado conoce la dirección IP de otro y le quiere enviar un paquete: antes de que el paquete pueda ser entregado al destinatario, el mismo deberá pasar por una interfaz física que sólo conoce direcciones propias a la red. Para poder determinar a quién debe entregarse el paquete, es necesario un mecanismo de traducción que reciba una dirección IP y devuelva una dirección de red apropiada.

ARP requiere que la red donde se implementa tenga soporte para enviar paquetes *broadcast*; eso es, paquetes cuyo destinatario sea toda la red. Eso permite que un host emita un mensaje a toda la red preguntando quién tiene una IP determinada (ese mensaje se denomina `who-has`). Cada host debe prestar atención a ese tipo de mensajes y, en caso de recibir uno que pregunte por su dirección IP, contestará con un mensaje *is-at* que contiene su dirección MAC. Este último mensaje no es necesario que sea emitido a toda la red, por lo tanto su destinatario será sólo el host que emitió el `who-has` (unicast).

Como vamos a analizar el tráfico de una red en general, enfocaremos nuestro análisis en los paquetes `who-has`, ya que por su naturaleza de ser broadcast vamos a poder recibirlos siempre en las capturas que realicemos, independientmente de si la red es Ethernet o WiFi. Podemos asumir que la mayoría de los mensajes `who-has` serán seguidos de un paquete entre el host que contiene la IP por la que se pregunta y el que hizo la pregunta (en el caso de que el host por el que se pregunta esté activo en la red).

## Nodos distinguidos
A partir de la captura de paquetes `who-has` del protocolo ARP, vamos a decir que un nodo es *distinguido* si recibe o envía una cantidad de mensajes mayor a la del resto de los nodos.

Por definición, un host que aparece más veces como destinatario tendrá una mayor frecuencia relativa dentro de todas las combinaciones de remitentes observadas en la red. En consecuencia, la información aportada por el mensaje será menor, ya que será de cierto modo predecible que alguien le enviará un mensaje a dicho host. Lo mismo será cierto, de forma análoga, para los hosts que más mensajes envíen: será más predecible encontrar un mensaje en la red donde aparezcan como remitentes.

Para establecer cuándo un nodo es distinguido para la recepción o para la transmisión, vamos a compararlo con la entropía de la fuente $S1$: **aquellos que aporten menos información que el valor de la entropía serán clasificados como distinguidos para cada sentido de la comunicación.**

## Red 1: Red hogareña
### Resultados
Capturamos 1004 paquetes `who-has` en la misma red de la primera parte. Entre ellos observamos 18 IPs únicas que aparecen como destino y 12 como fuente.

La entropía de la fuente, calculada a partir de la captura, es $H(S_1) = 3.9357$ bits.

\begin{figure}
\includegraphics[width=\linewidth]{graficos/red1-ej2-recibidos}
\caption{Información aportada por los paquetes capturados que contienen a cada IP como destino. La línea horizontal es la entropía, y las barras negras marcan los nodos que consideramos distinguidos.}
\label{red1:recibidos}
\end{figure}

\begin{figure}
\includegraphics[width=\linewidth]{graficos/red1-ej2-enviados}
\caption{Información aportada por los paquetes capturados que contienen a cada IP como fuente. La línea horizontal es la entropía, y las barras negras marcan los nodos que consideramos distinguidos.}
\label{red1:enviados}
\end{figure}

Vemos que el host en la dirección `192.168.1.1` es que más paquetes envió. Eso era esperable, ya que dicho host es el **gateway** de la red. Fue seguido de tres hosts: `192.168.1.`$\lbrace$`102, 141, 149`$\rbrace$.

Por otro lado, respecto a la recepción de paquetes, el gateway quedó en segundo lugar. El que más mensajes `who-has` recibió fue `192.168.1.4`, un host común de la red. Otro nodo distinguido fue `192.168.1.139`, otro host común---pero recibió considerablemente menos pedidos que `192.168.1.4`.

Una posible explicación para eso es que el servidor **DHCP** (*Dynamic Host Configuration Protocol*) que corre en el gateway está configurado para asignar esa IP en forma estática (cosa que no ocurre con ninguna otra dirección). Por lo tanto, la mayor frecuencia de solicitudes a esa IP podría ser el servidor asegurándose de que la IP se haya asignado al host correcto, para lo que necesita comparar la dirección física del host con la que tiene almacenada en su configuración.

Otros datos llamativos que se observan son la dirección `0.0.0.0`, que sólo envió mensajes; y las direcciones `169.254.197.216`, `169.254.197.216` y `169.254.255.255`, a las que se destinaron mensajes aún cuando no son direcciones IP válidas en la red.

Una rápida investigación sugiere que las direcciones inexistentes a las que se envían mensajes está relacionado con un conjunto de herramientas llamado *Zeroconf*[^Zeroconf], que permite configurar una red de manera descentralizada.

Uno de los mecanismos que se implementan es una forma de asignar direcciones IP en la ausencia de un servidor DHCP, las cuales se denominan *Link-local addresses*[^LLA]. En el RFC 3927 [^RFC3927] se describe cómo:
> *[...] a host may
   automatically configure an interface with an IPv4 address within the
   **169.254/16** prefix that is valid for communication with other devices connected to the same physical (or logical) link.*

Los pedidos desde la dirección `0.0.0.0` están relacionados a un mecanismo que permite que un host determine si una determinada dirección está actualmente en uso (RFC 5227 [^RFC5227]):
> *A host probes to see if an address is already in use by broadcasting
   an ARP Request for the desired address.  The client MUST fill in the
   'sender hardware address' field of the ARP Request with the hardware
   address of the interface through which it is sending the packet.  **The
   'sender IP address' field MUST be set to all zeroes**; this is to avoid
   polluting ARP caches in other hosts on the same link in the case
   where the address turns out to be already in use by another host.*


Otro caso especial de mensaje son los llamados *gratuitous ARP*, o "ARP no solicitados". En ese caso, un host envía un pedido `who-has` cuya direcciones de origen y de destino tienen el mismo valor: la dirección IP actual de dicho host. Lo envía sin haber sido preguntado---de ahí su nombre---y generalmente se hace cuando el sistema operativo inicializa o activa la interfaz de red para avisar a otros hosts que (nuevamente) está recibiendo mensajes en esa dirección MAC.
[^GratuitousARP]

[^Zeroconf]: https://en.wikipedia.org/wiki/Zero-configuration_networking
[^LLA]: https://en.wikipedia.org/wiki/Link-local_address
[^RFC3927]: https://tools.ietf.org/html/rfc3927
[^GratuitousARP]: https://wiki.wireshark.org/Gratuitous_ARP
[^RFC5227]: https://tools.ietf.org/html/rfc5227



## Red 2: Laboratorios DC
Se capturaron 1391 paquetes `who-has` en los laboratorios de la Facultad, en un instante en el cual se observaron más de 200 hosts conectados.

La entropía calculada de la fuente es $H(S_1) = 6.8753$ bits.


### Resultados
Detectamos 8 nodos distinguidos de los 214 a los que se envió algún mensaje, mostrados en la Tabla \ref{tabla:red2ndd}. Los mismos representan menos del 4\% de los hosts a los que se envió algún mensaje \textit{who-has}.

\begin{table}
\caption{Nodos distinguidos observando la direcciones IP de destino.}
\label{tabla:red2ndd}
\begin{tabular}{|l|r|r|}
\hline
IP & $p$($S_\text{dest.}$ == IP) & Info. [bits] \\
\hline
\textbf{10.2.203.254} & 0.2325 & 2.1048 \\
10.2.0.187 &  0.0585 & 4.0958 \\
10.2.0.67 & 0.0455 & 4.4584 \\
10.2.0.65 & 0.0455 & 4.4584 \\
10.2.0.64 & 0.0448 & 4.4815 \\
10.2.1.250 & 0.0260 & 5.2657 \\
169.254.255.255 & 0.0209 & 5.5777 \\
10.2.2.250 & 0.0173 & 5.8507 \\
10.2.0.190 & 0.0144 & 6.1137 \\
\hline
\end{tabular}
\end{table}

Además, detectamos 24 nodos distinguidos de de los 82 que enviaron algún mensaje, mostrados en la Tabla \ref{tabla:red2ndf}. Los mismos representan aproximadamente el 30\% de los hosts que enviaron algún mensaje \textit{who-has}.

\begin{table}
\caption{Nodos distinguidos observando la direcciones IP del emisor.}
\label{tabla:red2ndf}
\begin{tabular}{|l|r|r|}
\hline
IP & $p$($S_\text{fuente}$ == IP) & Info. [bits] \\
\hline
10.2.0.249   & 0.1372 & 2.8658 \\
10.2.202.213 & 0.0982 & 3.3482 \\
10.2.6.254   & 0.0946 & 3.4022 \\
\textbf{10.2.203.254} & 0.0650 & 3.9438 \\
10.2.0.187   & 0.0585 & 4.0958 \\
10.2.7.249   & 0.0491 & 4.3482 \\
10.2.1.254   & 0.0484 & 4.3696 \\
10.2.5.254   & 0.0332 & 4.9121 \\
10.2.201.60  & 0.0310 & 5.0094 \\
10.2.4.254   & 0.0303 & 5.0434 \\
10.2.2.254   & 0.0245 & 5.3482 \\
0.0.0.0      & 0.0238 & 5.3913 \\
10.2.201.235 & 0.0231 & 5.4357 \\
10.2.0.254   & 0.0217 & 5.5288 \\
10.2.2.249   & 0.0181 & 5.7918 \\
10.2.1.8     & 0.0173 & 5.8507 \\
10.2.200.220 & 0.0152 & 6.0434 \\
10.2.3.254   & 0.0137 & 6.1877 \\
10.2.3.249   & 0.0137 & 6.1877 \\
10.2.200.57  & 0.0130 & 6.2657 \\
10.2.2.8     & 0.0130 & 6.2657 \\
10.2.1.249   & 0.0123 & 6.3482 \\
10.2.201.81  & 0.0116 & 6.4357 \\
10.2.1.17    & 0.0087 & 6.8507 \\
\hline
\end{tabular}
\end{table}

La dirección `10.2.203.254` (en negrita) corresponde al *gateway* de la red. Nuevamente podemos observar cómo el gateway no fue el único nodo distinguido de la red, y, aunque fue el que más mensajes recibió, no fue el que más mensajes envió.

En el grafo de la Figura \ref{red2:grafo} se pueden observar distintas componentes conexas. Las mismas corresponden a las distintas subredes de la red. En el caso de los laboratorios de la Facultad, las dirección IP `10.2.L.W` corresponde a la máquina (*workstation*) *W* del laboratorio *L*.

Al realizar la captura, se nos asignó la dirección IP `10.2.200.204`, por lo que asumimos que las direcciones de la forma `10.2.{200, 201, 203}.x` se asignan a los dispositivos que se conectan mediante el access point inálambrico de los laboratorios.


\begin{figure}
\includegraphics[width=\linewidth]{graficos/red2-ej2-enviados}
\caption{Información aportada por los mensajes \texttt{who-has} enviados por los nodos distinguidos. La línea horizontal es la entropía $H(S)$.}
\label{red2:enviados}
\end{figure}

\begin{figure}
\includegraphics[width=\linewidth]{graficos/red2-ej2-recibidos}
\caption{Información aportada por los mensajes \texttt{who-has} enviados a nodos distinguidos. La línea horizontal es la entropía $H(S)$.}
\label{red2:recibidos}
\end{figure}



## Red 3
De nuevo analizamos los paquetes capturados en la sección anterior, que corresponden a una una red abierta en un local de la cafetería Starbucks.

### Resultados
Las figuras \ref{red3:enviados} y \ref{red3:recibidos} muestra la información aportada por cada nodo que envió y que fue enviado un mensaje `who-has`.

En este caso, la entropía calculada para la fuente es $H(S_1) = 3.7822$ bits.

En esta red determinamos tan sólo un nodo distinguido respecto a los mensajes que recibió: `10.254.70.1`. Dicha dirección recibió más del 71% de los mensajes y corresponde al gateway de la red.

Los nodos distinguidos con respecto a los mensajes `who-has` que enviaron fueron `10.254.70.{215, 232, 238}`---los cuales consideramos que son hosts comunes conectados a la red---además de la dirección especial `0.0.0.0`.


\begin{figure}
\includegraphics[width=\linewidth]{graficos/red3-ej2-enviados}
\caption{Información aportada por los mensajes \texttt{who-has} enviados por los nodos distinguidos. La línea horizontal es la entropía $H(S)$.}
\label{red3:enviados}
\end{figure}

\begin{figure}
\includegraphics[width=\linewidth]{graficos/red3-ej2-recibidos}
\caption{Información aportada por los mensajes \texttt{who-has} enviados a nodos distinguidos. La línea horizontal es la entropía $H(S)$.}
\label{red3:recibidos}
\end{figure}


## Conclusiones
Vimos cómo los paquetes ARP de una red permiten recrear, observando tan sólo ese tipo de tráfico, la organización de una red.

Luego de las experimentaciones realizadas, concluímos que utilizar el criterio de nodos distinguidos como mecanismo para encontrar el gateway de la red puede ser una heurística válida, pero no siempre es muy exacta (puede tener falsos positivos). Sin embargo podría servir como un punto de partida, para obtener un primer conjunto de nodos para seguir analizando en mayor profundidad.

Aprendimos sobre distintas sutilezas del protocolo ARP, como la detección de IPs enviando paquetes con la dirección `0.0.0.0` como fuente, y otras herramientas como *Zeroconf*, que crean tráfico en la red que en principio desconocíamos.


\onecolumn
\begin{figure}
\includegraphics[width=\linewidth]{graficos/red1-grafo}
\caption{Red ARP subyacente en la red 1}
\label{red1:grafo}
\end{figure}

\begin{figure}
\includegraphics[width=\linewidth]{graficos/red2-grafo2}
\caption{Red ARP subyacente en la red 2. Se puede observar la distinción entre nodos asignados a distintas subredes, que aparecen en componentes conexas distintas.}
\label{red2:grafo}
\end{figure}


\begin{figure}
\includegraphics[width=\linewidth]{graficos/red3-grafo}
\caption{Red ARP subyacente en la red 3}
\label{red3:grafo}
\end{figure}
\twocolumn