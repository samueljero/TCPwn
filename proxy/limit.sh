#!/bin/sh

iface1=eth1
iface2=eth2
speed=100Mbit #Most Systems
queue=500 #Most Systems
#speed=10Mbit #Windows 95
#queue=50 #Windows95

ifconfig $iface1 txqueuelen $queue
ifconfig $iface2 txqueuelen $queue

tc qdisc del root dev $iface1
tc qdisc del root dev $iface2

tc qdisc add dev $iface1 root handle 1:0 netem limit $queue rate $speed delay 10ms
tc qdisc add dev $iface2 root handle 1:0 netem limit $queue rate $speed delay 10ms

tc qdisc ls dev $iface1
tc qdisc ls dev $iface2
