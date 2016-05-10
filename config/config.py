# SDN Testing Config File
# Python syntax
import os

#Global
system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
logs_loc = system_home + "/logs/inst{instance}.log"
currently_testing = "Ubuntu 14.04"

#Baselining
stat_baseline_nrounds = 3

#Proxy
proxy_com_port = 1026
proxy_cmd = "/root/proxy/proxy -i eth1 -i eth2 -v -p {port}"
limit_cmd = "/root/proxy/limit.sh"

#Servers
server_start_cmd = "service apache2 restart"

#Clients
background_client_cmd = "wget http://10.0.3.4/bigfile"
main_client_cmd = "wget http://10.0.3.3/smallfile"

#Coordinator
coordinator_port = 3333

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
vm_replace_data = True
