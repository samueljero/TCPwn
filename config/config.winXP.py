# SDN Testing Config File
# Python syntax
import os
import socket

#Global
system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
logs_loc = system_home + "/logs/inst{instance}.log"
currently_testing = "Windows XP"
protocol = "TCP"

#Captures
do_capture = True
captures_loc = system_home + "/captures/{tm}-e{exe}.dmp"
captures_time_str = "%Y-%m-%d-%H-%M-%S"
capture_cmd = "tcpdump -i eth2 -s84 -w - tcp > /root/capture.dmp"
capture_kill_cmd = "pkill tcpdump"


#Baselining
stat_baseline_nrounds = 20

#Proxy
proxy_com_port = 1026
proxy_cmd = "/root/proxy/proxy -i eth1 -i eth2 -v -p {port}"
limit_cmd = "/root/proxy/limit.sh"
proxy_kill_cmd = "pkill proxy"

#Monitor
monitor_com_port = 4444
monitor_cmd = "/root/monitor/monitor -i eth1 -i eth2 -v -p {port} -o {proxy}:{proxyport}"
monitor_kill_cmd = "pkill monitor"

#Servers
server_start_cmd = "service apache2 restart"
background_server_config = ""
target_server_ip = "10.0.3.3"
background_server_ip = "10.0.3.4"

#Clients
background_client_cmd = "curl -o /dev/null -m {tm} http://10.0.3.4/bigfile"
main_client_cmd = "curl -o /dev/null -m {tm} http://10.0.3.3/bigfile"
target_client_ip = "10.0.3.1"
background_client_ip = "10.0.3.2"

#Coordinator
coordinator_port = 3333
failed_retries = 1
coord_strategy_generation_algorithm = "StateBased"
coord_strategy_generation_state_machine_file = system_home + "/config/tcp-newreno.xml"
coord_strategy_generation_state_machine_search = "cwnd"
coord_checkpoint_file = system_home + "/logs/coord.ck"
coord_log = system_home + "/logs/coord.log"
coord_results_log = system_home + "/logs/results.log"
email_on_system_fail = False
dst_email_address = ""
src_email_address = "cctester@" + socket.getfqdn()

#Test
max_time = 60
transfer_size = 100*1024*1024
transfer_multiple = 0.7
test_max_idle = 10
#test_results_avg =
#test_results_stddev =

#VM Section
vm_path = system_home + "/vms/"
master_name = "/ubuntu-1404-master.qcow2"
vm_name_bases = ["client", "client","windowsXP-server","server", "tc", "track"]
vm_net = [["tap-n{n}-b1-h0"],["tap-n{n}-b1-h1"],["tap-n{n}-b3-h0"],["tap-n{n}-b2-h1"],["tap-n{n}-b1-h2","tap-n{n}-b2-h2"], ["tap-n{n}-b3-h1","tap-n{n}-b2-h0"]]
vm_has_ssh = [True,True,False,True,True,True]
vm_can_ping = [True,True,True,True,True,True]
vm_cores =  ["2","2","2","2","4","2"]
vm_user = "root"
vm_ip_base = "10.0.1.{0}"
vm_ram = "2048"
vm_telnet_base = 10100
vm_vnc_base = 1
vm_ssh_key = system_home + "/config/ssh.key"
vm_replace_data = True
