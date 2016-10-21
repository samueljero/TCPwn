# Author: Samuel Jero
reset

P=1
EPS="TimingGraph.svg"

if ( P == 1 ) {
set term svg size 10000,2048 dynamic enhanced
set object 1 rect from screen 0, 0, 0 to screen 1, 1, 0 behind
set object 1 rect fc  rgb "white"  fillstyle solid 1.0
#set term postscript eps enhanced color 12 size 12in, 2in
}
unset log
unset label
set datafile commentschars "#"

if (P == 1) {
set output EPS
}
set autoscale
set grid noxtics ytics
set key top left
set title "Time to Completion for our Tests"
set xlabel "Test"
set ylabel "Time to Complete Test (download 100MB) in seconds"
set boxwidth 0.9 absolute
set style fill solid 1.00 border -1
set style data histograms
unset key
set xtics out rotate by -60
#unset xtics
set yrange [0:]
set xrange [0:]
set style line 2 lw 4 lc rgb "blue"
set style line 3 lw 4 lc rgb "orange"
plot "./data.txt" using 2:xticlabels(1) ti col, 16.15 title "" with lines ls 2, 17.73 title "" with lines ls 2, \
"./data.txt" using (100-($3/(1024*1024))):xticlabels(1) ti col, (100*0.2) with lines ls 3
#Wait until user hits enter to exit
if (P == 0) {
pause -1
}
