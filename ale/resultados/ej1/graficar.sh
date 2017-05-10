#!/bin/bash
inputfile="${1}"

if [ "$#" -ne 1 ]; then
    echo "Falta el archivo de entrada"
    exit -1
fi

outputfile=`echo "$inputfile" | cut -d '.' -f 1`

gnuplot -c ej1-info.plot "$inputfile" "${outputfile}-info.pdf"
gnuplot -c ej1-proba.plot "$inputfile" "${outputfile}-proba.pdf"