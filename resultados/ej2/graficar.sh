#!/bin/bash
inputfile="${1}"

if [ "$#" -ne 1 ]; then
    echo "Falta el archivo de entrada"
    exit -1
fi

outputfile=`echo "$inputfile" | cut -d '.' -f 1`

gnuplot -c packets-sent.plot "$inputfile" "${outputfile}-enviados.pdf"
gnuplot -c packets-received.plot "$inputfile" "${outputfile}-recibidos.pdf"
