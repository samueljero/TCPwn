#!/bin/sh

iface1=eth1
iface2=eth2

tc qdisc del root dev $iface1
tc qdisc del root dev $iface2

tc qdisc add dev $iface1 root handle 1:0 netem delay 10ms
tc qdisc add dev $iface2 root handle 1:0 netem delay 10ms
tc qdisc add dev $iface1 parent 1:1 handle 10: tbf rate 100Mbit latency 20ms burst 10Mb
tc qdisc add dev $iface2 parent 1:1 handle 10: tbf rate 100Mbit latency 20ms burst 10Mb

tc qdisc ls dev $iface1
tc qdisc ls dev $iface2
