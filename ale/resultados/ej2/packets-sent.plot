set datafile separator ","
#set style data histogram
#set style histogram clustered gap 1
set boxwidth 0.2

#set key top right
set key off

#set yrange [0:1]
#set xrange[-0.3:1.3]

set tics out
set tics font ",15"
set grid

set xtics rotate 90

set boxwidth 0.3
set style fill solid border rgb "grey30"

set terminal pdf enhanced
set output ARG2

#set key autotitle columnhead

inputFile=ARG1

entropy=system("grep 'Entropía' ".inputFile." | cut -d '=' -f 2") + 0

set title "Información de los paquetes who-has enviados por IP"
set y2label "Información [bits]"


plot inputFile every 1::1 using 0:2:($2<=entropy? 0x000000 : 0x808080):xticlabels(1) with boxes lc rgb variable, \
	 entropy with lines lc rgb "black" lw 1.5 title "Entropía"