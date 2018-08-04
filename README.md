TCPwn
==========================================

TCPwn is a system for testing TCP implementations for bugs and vulnerabilities related to congestion control.

## Prerequisites
In order to build and run TCPwn, the following are required:
* C/C++ compiler
* Python 2.7
* Qemu (Tested with 1.7.0 / 2.3.0)
* tunctl (uml-ultities package on Ubuntu)
* brctl (bridge-utils package on Ubuntu)
* dhcp server and restart script that can be called as: `/usr/local/sbin/restart-dhcpd < mac-ip-mapping`
* Limited root access. In particular, the ability to run the following commands:

		/usr/bin/tunctl -u [a-z]* -t tap*
		/usr/bin/tunctl -d tap*
		/bin/ifconfig tap* hw ether 00:00:00:*:*:*
		/bin/ifconfig tap* up
		/bin/ifconfig tap* 0.0.0.0 up
		/bin/ifconfig tap* 10.0.*.* netmask 255.255.*.* up
		/bin/ifconfig tap* down
		/bin/ifconfig br* up
		/bin/ifconfig br* 10.0.*.* netmask 255.255.*.* up
		/bin/ifconfig br* down
		/sbin/brctl addbr br*
		/sbin/brctl delbr br*
		/sbin/brctl addif br* tap*
		/sbin/brctl delif br* tap*
		/usr/local/sbin/restart-dhcpd
		/bin/ifconfig tap*

Not required, but useful:
* screen
* gnuplot
* Wireshark
* tcptrace (http://tcptrace.org)
* xplot for tcptrace (http://tcptrace.org)

## Installation
* Clone the code:

		git clone https://github.com/samueljero/TCPwn.git
		cd TCPwn

* Build Proxy, Monitor, and State Searcher:

		make

* Download the VMs:

		cd vms/
		wget http://www.cs.purdue.edu/~sjero/tcpwn_vms.tar.gz
		(or http://sjero.net/ds2/tcpwn_vms.tar.gz)
		tar xf tcpwn_vms.tar.gz

	 For reference, the username for all VMs is `root` and the password is `Gat11ng`. They already have an SSH key installed to allow our testing system passwordless access.

* Ensure private SSH Key for VMs has proper permissions:

		chmod 600 config/ssh.key

* Configure the Virtual Network Environment:

		./executor/network_setup.py start 1 1

	This script creates entire test network instances. The numbers are the first and last instances to create.

* Choose a config file:

	There is a different config file for each implementation. The VM's we provide are Ubuntu 14.04, so:

		cd config
		cp config.1404.py config.py

At this point the system should be operational.

## Usage

* There are two components, a coordinator and an executor

* Since this testing will take many hours to complete, I recommend running these components in `screen`.

* In one terminal, run the coordinator to generate test strategies and output results:

		./coordinator/coordinator.py

* In another terminal, start an executor to actually do the testing:

		./executor/run.py -c localhost -i 0

	(-c uses the specified coordinator, -i sets the instance number)

	You can start multiple executors to parallize the testing. These executors will start the VMs, proxy, and state tracker and perform the testing. They are directed by the coordinator and report their findings back to it.

* Once testing completes, save the results:

		mv logs logs.YYYMMDD
		mv captures captures.YYYMMDD
		git checkout logs/.placeholder
		git checkout captures/.placeholder

	This saves the output directories (`logs/` and `captures/`) and resets the system.


## Analysis

To analyize the results, there are a couple scripts in the `utils/` directory:

`utils/viewer.py` walks through every report in the `results.log` file and allows you to easily see the strategies and results. It also gives you easy access to the details of the test (from `inst*.log`) and the captures.

`utils/qv.py` (quick view) parses the `results.log` and spits out something that is a little easier for humans to read

`utils/timingGraph.py` generates an output file that can be used with `gnuplot utils/timingGraph.gnu` to produce a graph showing performance for each test (both time spent to download and amount of file downloaded).

While the `inst*.log` files can contain interesting info about the test, I've found that looking at the captures is the best way to figure out what's going on. I usually use `tcptrace` and `xplot` to examine the results. These tools graphically display a TCP connection and show you what's going on, specifically when packets and acknowledgements were sent and what data they sent or acknowledge.



## Test Network Diagram

    10.0.1.1                                  10.0.1.6            10.0.1.3
    |                                          |                     |
    Client 1                                 Monitor --------- Server 1 (Target Implementation)
    (10.0.3.1)                            (eth1)  (eth2)      (10.0.3.3)
                \                         /
                br (eth1) Proxy  (eth2) br
                /            |           \
    (10.0.3.2)               |           (10.0.3.4)
    Client 2                 |             Server 2
    |                        |                 |
    10.0.1.2                 |             10.0.1.4
                             |
                          10.0.1.5

Each VM may have up to three IP addresses:  
10.0.1.x which is connected to the host via the brhost bridge  
10.0.3.x (where x is between 1 and 4). This address is actually connected to the testing system.  
10.0.2.x this is a NATed address to the global internet. I find myself wanting to install software (gdb, etc) for debugging and its a pain to not have this configured by default.  

Note that 10.0.1.x addresses are unique to each VM while 10.0.3.x addresses are repeated for each instance (i.e. both instance 1 and instance 2 will have hosts with address 10.0.3.1---since they are completely isolated from each other this isn't a problem. Those machines would have addresses 10.0.1.3 and 10.0.1.9, respectively from the host).



## FAQ

**Q)Sometimes I get this line "Main Traffic Command Failed! Return Code: XX", where XX is the return code.**  
A)If you are running actual tests that's nothing to be concerned about. The return code being referred to is from the `wget` command we use to generate the connection we are manipulating. If that connection doesn't complete or times out, then you'll see the return code message. This usually occurs because the strategy being tested caused our connection to stall or become extremely slow.

**Q)How can I access the VM console, if something goes wrong**  
A)Use VNC. However, VNC is tied to the localhost to prevent it from being reachable from the global internet with no password. As a result, I usually use SSH port forwarding.

**Q)Can I start VMs manually before the test**  
A)You start the VMs manually with `executor/manage_vms.py start <first_vm_num> <last_vm_num>`. If you then run `executor/run.py`, it will emit a warning when it tries to start the VMs and they are already running, but shouldn't fail or crash. It should continue with the testing. For most VMs it will check that they are up and continue just fine.

## Paper

This system was published in:

Samuel Jero, Endadul Hoque, David Choffnes, Alan Mislove, and Cristina Nita-Rotaru. **Automated Attack Discovery in TCP Congestion Control Using a Model-guided Approach**, Network and Distributed Systems Security Symposium (NDSS), February 2018.

Samuel Jero  
<sjero@sjero.net>
