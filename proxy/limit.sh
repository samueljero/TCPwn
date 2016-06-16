#!/bin/sh

iface1=eth1
iface2=eth2
#speed=100Mbit
speed=10Mbit

ifconfig $iface1 txqueuelen 50
ifconfig $iface2 txqueuelen 50

tc qdisc del root dev $iface1
tc qdisc del root dev $iface2

tc qdisc add dev $iface1 root handle 1:0 netem limit 50 rate $speed delay 10ms
tc qdisc add dev $iface2 root handle 1:0 netem limit 50 rate $speed delay 10ms

tc qdisc ls dev $iface1
tc qdisc ls dev $iface2
