set datafile separator ","
#set style data histogram
set style histogram clustered gap 1

#set key top right
set key off

set autoscale x
set yrange [0:2.5]
set xrange [-0.3:2.3]

set tics out
set tics font ",15"
set grid

set boxwidth 0.3
set style fill solid border rgb "grey30"

set terminal pdf enhanced
set output ARG2

#set key autotitle columnhead

inputFile=ARG1

#set title "Información de cada símbolo vs. entropía de la fuente"
set y2label "[Bit]"

plot inputFile every ::1::1 using (0):4:xtic(1):ytic(4) with boxes lc rgb 'grey90' lt 1 lw 2, \
	 "" every ::2::2 using (1):4:xtic(1):ytic(4) with boxes lc rgb 'grey70' lt 1 lw 2, \
	 "" every ::3::3 using (2):4:xtic(1):ytic(4) with boxes lc rgb 'grey50' lt 1 lw 2
