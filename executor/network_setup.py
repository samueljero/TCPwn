#!/usr/bin/env python
# Samuel Jero <sjero@purdue.edu>
# Network setup script

import os
import argparse
import sys

user = os.getlogin()

def do_network(cmd, num):
	global user

	if cmd == "start":
                #Host bridge
		os.system("sudo brctl addbr brhost")
		os.system("sudo ifconfig brhost 10.0.0.1 netmask 255.255.0.0 up")
                os.system("touch /tmp/ip-mac")
		os.system("echo \"\" >> /tmp/ip-mac")
                #Host VM taps and DHCP config
		for i in range(0,6):
			os.system("sudo tunctl -u {0} -t tap-n{1}-h{2}".format(user, str(num),str(i)))
			os.system("sudo ifconfig tap-n{0}-h{1} 0.0.0.0 up".format(str(num),str(i)))
			os.system("sudo brctl addif brhost tap-n{0}-h{1}".format(str(num),str(i)))
			os.system("echo \"10.0.1.{:d} 00:00:00:01:00:{:02X}\" >> /tmp/ip-mac".format((num-1)*6+i+1,(num-1)*6+i+1))
                #Create Bridges
                os.system("sudo brctl addbr br-n{0}-1".format(str(num)))
                os.system("sudo brctl addbr br-n{0}-2".format(str(num)))
                os.system("sudo brctl addbr br-n{0}-3".format(str(num)))
                os.system("sudo ifconfig br-n{0}-1 up".format(str(num)))
                os.system("sudo ifconfig br-n{0}-2 up".format(str(num)))
                os.system("sudo ifconfig br-n{0}-3 up".format(str(num)))
                os.system("sudo ifconfig br-n{0}-1 txqueuelen 50".format(str(num)))
                os.system("sudo ifconfig br-n{0}-2 txqueuelen 50".format(str(num)))
                os.system("sudo ifconfig br-n{0}-3 txqueuelen 50".format(str(num)))
                #Create Main Network
		for i in range(0,3):
			os.system("sudo tunctl -u {0} -t tap-n{1}-b1-h{2}".format(user, str(num),str(i)))
			os.system("sudo ifconfig tap-n{0}-b1-h{1} 0.0.0.0 up".format(str(num),str(i)))
			os.system("sudo ifconfig tap-n{0}-b1-h{1} txqueuelen 50".format(str(num),str(i)))
			os.system("sudo brctl addif br-n{0}-1 tap-n{0}-b1-h{1}".format(str(num),str(i)))
		for i in range(0,3):
			os.system("sudo tunctl -u {0} -t tap-n{1}-b2-h{2}".format(user, str(num),str(i)))
			os.system("sudo ifconfig tap-n{0}-b2-h{1} 0.0.0.0 up".format(str(num),str(i)))
			os.system("sudo ifconfig tap-n{0}-b2-h{1} txqueuelen 50".format(str(num),str(i)))
			os.system("sudo brctl addif br-n{0}-2 tap-n{0}-b2-h{1}".format(str(num),str(i)))
		for i in range(0,2):
			os.system("sudo tunctl -u {0} -t tap-n{1}-b3-h{2}".format(user, str(num),str(i)))
			os.system("sudo ifconfig tap-n{0}-b3-h{1} 0.0.0.0 up".format(str(num),str(i)))
			os.system("sudo ifconfig tap-n{0}-b3-h{1} txqueuelen 50".format(str(num),str(i)))
			os.system("sudo brctl addif br-n{0}-3 tap-n{0}-b3-h{1}".format(str(num),str(i)))
                #Restart DHCP
		os.system("sudo /usr/local/sbin/restart-dhcpd < /tmp/ip-mac")
	elif cmd == "stop":
                #Remove main network
		for i in range(0,3):
			os.system("sudo ifconfig tap-n{0}-b1-h{1} down".format(str(num),str(i)))
			os.system("sudo brctl delif br-n{0}-1 tap-n{0}-b1-h{1}".format(str(num),str(i)))
			os.system("sudo tunctl -d tap-n{1}-b1-h{2}".format(user, str(num),str(i)))
		for i in range(0,3):
			os.system("sudo ifconfig tap-n{0}-b2-h{1} down".format(str(num),str(i)))
			os.system("sudo brctl delif br-n{0}-2 tap-n{0}-b2-h{1}".format(str(num),str(i)))
			os.system("sudo tunctl -d tap-n{1}-b2-h{2}".format(user, str(num),str(i)))
		for i in range(0,2):
			os.system("sudo ifconfig tap-n{0}-b3-h{1} down".format(str(num),str(i)))
			os.system("sudo brctl delif br-n{0}-3 tap-n{0}-b3-h{1}".format(str(num),str(i)))
			os.system("sudo tunctl -d tap-n{1}-b3-h{2}".format(user, str(num),str(i)))
                #Remove Bridges
                os.system("sudo ifconfig br-n{0}-1 down".format(str(num)))
                os.system("sudo ifconfig br-n{0}-2 down".format(str(num)))
                os.system("sudo ifconfig br-n{0}-3 down".format(str(num)))
                os.system("sudo brctl delbr br-n{0}-1".format(str(num)))
                os.system("sudo brctl delbr br-n{0}-2".format(str(num)))
                os.system("sudo brctl delbr br-n{0}-3".format(str(num)))
                #Remove VM taps
		for i in range(0,6):
			os.system("sudo ifconfig tap-n{0}-h{1} down".format(str(num),str(i)))
			os.system("sudo brctl delif brhost tap-n{0}-h{1}".format(str(num),str(i)))
			os.system("sudo tunctl -d tap-n{1}-h{2}".format(user, str(num),str(i)))
                #Remove Host Bridge
		os.system("sudo ifconfig brhost down")
		os.system("sudo brctl delbr brhost")
                #Cleanup DHCP
		os.system("rm /tmp/ip-mac")
	else:
		return False
	return True

if __name__ == "__main__":
	if len(sys.argv)!= 4:
		print "Usage: network_setup.py start|stop start end"
		sys.exit()

	cmd = sys.argv[1]
	start = int(sys.argv[2])
	end = int(sys.argv[3]) + 1
        for i in range(start, end):
    	    do_network(cmd, i)
