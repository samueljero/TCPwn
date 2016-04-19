# SDN Testing Config File
# Python syntax
import os

#Global
system_home = os.path.dirname(os.path.realpath(__file__))
#system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
#logs_loc = system_home + "/logs/inst{instance}.log"
#enable_stat = True

#VM Section
vm_path = system_home + "/vms/"
master_name = "/ubuntu-1404-master.qcow2"
vm_name_bases = ["client", "client","server","server", "tc"]
vm_net = [["tap-n{n}-b1-h0"],["tap-n{n}-b1-h1"],["tap-n{n}-b2-h0"],["tap-n{n}-b2-h1"],["tap-n{n}-b1-h2","tap-n{n}-b2-h2"]]
vm_user = "root"
vm_ip_base = "10.0.1.{0}"
vm_ram = "2048"
vm_cores = "2"
vm_telnet_base = 10100
vm_vnc_base = 1
vm_ssh_key = system_home + "/config/ssh.key"
