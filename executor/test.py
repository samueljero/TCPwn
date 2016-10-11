# Samuel Jero <sjero@purdue.edu>
# Actual strategy test routines
import manage_vms as mv
import os
import sys
import shlex
import subprocess
import time
from datetime import datetime
import socket
import struct
import threading
import numpy

system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
lib_path = os.path.abspath(os.path.join(system_home, 'executor', 'libs'))
config_path = os.path.abspath(os.path.join(system_home, 'config'))
proxy_path = os.path.abspath(os.path.join(system_home, 'proxy'))
monitor_path = os.path.abspath(os.path.join(system_home, 'monitor'))
sys.path.insert(1, lib_path)
sys.path.insert(0, config_path)
import config
import spur
from scapy.all import *



class CCTester:

    def __init__(self, instance, log):
        self.instance = instance
        self.clients = [instance*len(config.vm_name_bases)+1, instance*len(config.vm_name_bases)+2]
        self.servers = [instance*len(config.vm_name_bases)+3, instance*len(config.vm_name_bases)+4]
        self.tc = [instance*len(config.vm_name_bases)+5]
        self.mon = [instance*len(config.vm_name_bases)+6]
        self.log = log
        self.testnum = 1
        self.creating_baseline = False
        self.timers = []
        self.result_high_threshold = 0
        self.result_low_threshold = 0
        self.last_result = 0
        self.last_transfer = 0
        self.do_capture = config.do_capture
        self.last_cap = ""
        self.monitor_running = False
        self.proxy_running = False

    def baseline(self):
        self.creating_baseline = True
        num = self.testnum

        # Do Baseline
        self.result_high_threshold = self.result_low_threshold = 0
        perf_measurements = []
        i = 0
        while i < config.stat_baseline_nrounds:
            self.testnum = 0
            print "[%s] Baseline round %d." % (str(datetime.today()), i)
            res = self.doTest(None)
            if res[0] == False:
                print "Warning!!! Baseline failed!!!"
                continue
            else:
                perf_measurements.append(self.last_result)
            i += 1
        
        self.testnum = num
        self.creating_baseline = False

        #Compute threshold
        avg  = sum(perf_measurements)/len(perf_measurements)
        stddev = numpy.std(perf_measurements)
        self.result_high_threshold = avg + 2*stddev
        self.result_low_threshold = avg - 2*stddev

        # Log Thresholds
        decor = '$' * 40 + ' Thresholds ' + '$' * 40 + '\n'
        self.log.write(decor)
        self.log.write("Average: " + str(avg) + "\n")
        self.log.write("Standard Deviation: " + str(stddev) + "\n")
        self.log.write("High Threshold: " + str(self.result_high_threshold) + "\n")
        self.log.write("Low Threshold: " + str(self.result_low_threshold) + "\n")
        self.log.write(decor)
        self.log.flush()

    def retrieve_feedback(self):
        return {'high':self.result_high_threshold,'low':self.result_low_threshold,'last':self.last_result, 'bytes':self.last_transfer, 'capture':self.last_cap}

    def doTest(self, strategy):
        """
        :return [True | False, str]: First boolean value indicates pass or fail,
        	followed by an explanation
        """
        self.last_result = 0
        result = [True, "Success!"]
        self.log.write('#' * 30 + "Starting Test " + str(self.testnum) + '#' * 30 + '\n')
        self.log.write(str(datetime.today()) + "\n")

        #Cleanup anything leftover from prior tests
        self._cleanup()

        #Start monitor
        monitor = self._start_monitor()
        if monitor is None:
            return (False, "System Failure")

        # Start Proxy
        proxy = self._start_proxy()
        if proxy is None:
            self._stop_monitor(monitor)
            return (False, "System Failure")

        # Send Proxy Strategy
        if self._send_proxy_strategy(strategy) == False:
            self._stop_proxy(proxy)
            self._stop_monitor(monitor)
            return (False, "System Failure")

        #Start capture, if needed
        cap = None
        if self.do_capture:
            cap = self._start_capture()
    
        # Do Test
        res = self._call_test()
        res = (res[0], res[1], config.transfer_size)
        if res[0] is False:
            self._stop_proxy(proxy)
            self._stop_capture(cap)
            self._stop_monitor(monitor)
            return (False, "System Failure")

        #Stop and Process Capture
        if self.do_capture:
            self._stop_capture(cap)
            #res = self._process_capture()
            self._compress_capture()
        res = self._query_proxy_conn_info()


        # Evaluate Results
        print "Transfer Time " + str(res[1])
        print "Data Transfered " + str(res[2])
        self.log.write("Transfer Time " + str(res[1]) + "\n")
        self.log.write("Data Transfered " + str(res[2]) + "\n")
        self.last_result = res[1]
        self.last_transfer = res[2]
        if self.result_low_threshold > 0 and self.result_high_threshold > 0:
            if self.last_result < self.result_low_threshold:
                if self.last_transfer < (config.transfer_size * config.transfer_multiple):
                    result[0] = False
                    result[1] = "Stalled Connection"
                else:
                    result[0] = False
                    result[1] = "Performance -- Faster"
            if self.last_result > self.result_high_threshold:
                result[0] = False
                result[1] = "Performance -- Slower"

        # Stop Proxy
        if not self._stop_proxy(proxy):
            return (False, "System Failure")

        # Stop Monitor
        if not self._stop_monitor(monitor):
            return (False, "System Failure")

        # Cleanup anything still around
        self._cleanup()

        # Log
        self.log.flush()
        self.log.write("*****************\n")
        self.log.write("Test Result: " + str(result[0]) + ", Reason: " + str(result[1]) + "\n")
        self.log.write("Performance: " + str(self.last_result) + "\n")
        self.log.write("Thresholds: Low " + str(self.result_low_threshold) + ", High " + str(self.result_high_threshold) + "\n")
        self.log.write("Bytes: " + str(self.last_transfer) + "\n")
        self.log.write("Capture: " + str(self.last_cap) + "\n")
        self.log.write(str(datetime.today()) + "\n")
        self.log.write("##############################Ending Test " +
                       str(self.testnum) + "###################################\n")
        self.log.flush()
        self.testnum += 1
        return result

    def startVms(self):
        for c in self.clients:
            mv.startvm(c)
        for s in self.servers:
            mv.startvm(s)
        for t in self.tc:
            mv.startvm(t)
        for m in self.mon:
            mv.startvm(m)
        for c in self.clients:
            if(self._waitListening(mv.vm2ip(c), 22, 240, True) == False):
                print "Error: client VM %d not started!" % (c)
                return False
        for s in self.servers:
            if(self._waitListening(mv.vm2ip(s), 22 if mv.vmHasSSH(s) else 80, 240, True) == False):
                print "Error: server VM %d not started!" % (s)
                return False
        for t in self.tc:
            if(self._waitListening(mv.vm2ip(t), 22, 240, True) == False):
                print "Error: Traffic Shaping VM %d not started!" % (t)
                return False
            else:
                if config.vm_replace_data:
                    os.system("scp -r -p -i %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -r %s %s@%s:~\n" %
                              (config.vm_ssh_key, proxy_path, config.vm_user, mv.vm2ip(t)))
                    shell = spur.SshShell(hostname=mv.vm2ip(t), username=config.vm_user,
                                          missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
                    proc = shell.run(
                        ["/bin/bash", "-i", "-c", "cd proxy && make clean && make"])
                    if proc.return_code is not 0:
                        print "Error: Make failed!"
                        return False
        for m in self.mon:
            if(self._waitListening(mv.vm2ip(m), 22, 240, True) == False):
                print "Error: Monitor VM %d not started!" % (t)
                return False
            else:
                if config.vm_replace_data:
                    os.system("scp -r -p -i %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -r %s %s@%s:~\n" %
                              (config.vm_ssh_key, monitor_path, config.vm_user, mv.vm2ip(m)))
                    shell = spur.SshShell(hostname=mv.vm2ip(m), username=config.vm_user,
                                          missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
                    proc = shell.run(
                        ["/bin/bash", "-i", "-c", "cd monitor && make clean && make"])
                    if proc.return_code is not 0:
                        print "Error: Make failed!"
                        return False

        return True

    def stopVms(self):
        for c in self.clients:
            mv.stopvm(c)
        for s in self.servers:
            mv.stopvm(s)
        for t in self.tc:
            mv.stopvm(t)
        for m in self.mon:
            mv.stopvm(m)

    def _start_monitor(self):
        monitor = None
        ts = time.time()
        cmd = config.monitor_cmd.format(port = str(config.monitor_com_port))
        self.log.write("Monitor CMD: " + cmd + "\n")
        
        shell = spur.SshShell(hostname = mv.vm2ip(self.mon[0]),username = config.vm_user,
                                  missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
        #Start Proxy
        monitor = shell.spawn(["/bin/bash", "-i", "-c", cmd], store_pid=True, allow_error=True)
        if not monitor.is_running():
            res = monitor.wait_for_result()
            self.log.write("Monitor Failed to Start: " + res.output + res.stderr_output)
            return None
        else:
            self.log.write("Started monitor on " + str(mv.vm2ip(self.mon[0]))+ "...\n")
        
        #Wait for proxy to come up
        if(self._waitListening(mv.vm2ip(self.mon[0]), config.monitor_com_port, 240, False) == False):
            self.log.write("Monitor Failed to start after 240 seconds!\n")
            print "Monitor Failed to Start after 240 seconds!"
            return None
        
        self.log.write('[timer] Start monitor: %f sec.\n' % (time.time() - ts))
        self.monitor_running = True
        return monitor

    def _start_proxy(self):
        proxy = None
        ts = time.time()
        cmd = config.proxy_cmd.format(port=str(config.proxy_com_port))
        self.log.write("Proxy CMD: " + cmd + "\n")
        
        shell = spur.SshShell(hostname = mv.vm2ip(self.tc[0]),username = config.vm_user,
                                  missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)

        #Setup NetEM
        try:
            ret = shell.run(["/bin/bash", "-i", "-c", config.limit_cmd])
            self.log.write("Setting up netem:\n" + ret.output)
        except Exception as e:
            print "Setting up netem failed: " + str(e)
            self.log.write("Setting up netem failed: " + str(e) + "\n")
            return None

        #Start Proxy
        proxy = shell.spawn(["/bin/bash", "-i", "-c", cmd], store_pid=True, allow_error=True)
        if not proxy.is_running():
            res = proxy.wait_for_result()
            self.log.write("Proxy Failed to Start: " + res.output + res.stderr_output)
            return None
        else:
            self.log.write("Started proxy on " + str(mv.vm2ip(self.tc[0]))+ "...\n")

        #Wait for proxy to come up
        if(self._waitListening(mv.vm2ip(self.tc[0]), config.proxy_com_port, 240, False) == False):
            self.log.write("Proxy Failed to start after 240 seconds!\n")
            print "Proxy Failed to Start after 240 seconds!"
            return None
        self.log.write('[timer] Start proxy: %f sec.\n' % (time.time() - ts))
        self.proxy_running = True
        return proxy

    def _call_test(self):
        ts = time.time()

        #Start servers
        for s in self.servers:
            if mv.vmHasSSH(s):
                shell = spur.SshShell(hostname=mv.vm2ip(s), username=config.vm_user,
                              missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
                try:
                    ret = shell.run(["/bin/bash", "-i", "-c", config.server_start_cmd])
                except Exception as e:
                    print "Failed to start server"
                    self.log.write("Failed to start server\n")
                    return False,0
            if(self._waitListening(mv.vm2ip(s),80, 240, False) == False):
                print "Failed to start server"
                self.log.write("Failed to start server\n")
                return False,0
        self.log.write("Servers Started...\n")

        time.sleep(0.5)

        #Start background traffic
        shell = spur.SshShell(hostname=mv.vm2ip(self.clients[1]), username=config.vm_user,
                              missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
        background = shell.spawn(["/bin/bash", "-i", "-c", config.background_client_cmd.format(tm=str(config.max_time))],store_pid=True,allow_error=True)
        if not background.is_running():
            ret = background.wait_for_result()
            print "Background traffic command failed: %s %s" % (ret.output, ret.stderr_output)
            self.log.write("Background traffic command failed: %s %s\n" % (ret.output, ret.stderr_output))
            return False, 0
        bts = time.time()

        #Start main traffic
        shell = spur.SshShell(hostname=mv.vm2ip(self.clients[0]), username=config.vm_user,
                              missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
        mts = time.time()
        ret = None
        speed = 0
        bspeed = 0
        main = shell.spawn(["/bin/bash", "-i", "-c", config.main_client_cmd.format(tm=str(config.max_time))],store_pid=True,allow_error=True)
        if not main.is_running():
            ret = main.wait_for_result()
            print "Main Traffic Command failed: %s %s" % (ret.output, ret.stderr_output)
            self.log.write("Main Traffic Command Failed: %s %s\n" % (ret.output,ret.stderr_output))
            try:
                background.send_signal(2)
            except Exception as e:
                pass
            return False, 0

        #Wait to finish
        while background.is_running() or main.is_running():
            if background.is_running():
                bspeed = time.time() - bts
            if main.is_running():
                speed = time.time()  - mts
            if self._query_proxy_done():
                try:
                    background.send_signal(2)
                except Exception as e:
                    pass
                try:
                    main.send_signal(2)
                except Exception as e:
                    pass
                break
            time.sleep(1)

        #Check Main Return code
        ret = main.wait_for_result()
        if ret.return_code is not 0:
            self.log.write("Main Traffic Command Failed! Return Code: %d\n" % (ret.return_code))
            print "Main Traffic Command Failed! Return Code: %d" % (ret.return_code)
            speed = config.max_time
        self.log.write("Main Traffic command output: \n" + ret.stderr_output)

        #Check Background Return code
        ret = background.wait_for_result()
        if ret.return_code is not 0:
            self.log.write("Background Traffic Command Failed! Return Code: %d\n" % (ret.return_code))
            print "Background Traffic Command Failed! Return Code: %d" % (ret.return_code)
            bspeed = config.max_time
        self.log.write("Background Traffic command output: \n" + ret.stderr_output)

        return True, speed

    def _stop_proxy(self, proxy):
        if self.proxy_running is False:
            return True
        ts = time.time()

        #Check whether proxy is still running
        if not proxy.is_running():
            print "Proxy has crashed!!!\n"
            self.log.write("Proxy has crashed!!!\n")
            self.log.flush()
            return False

        #Stop Proxy
        proxy.send_signal(2)
        ret = proxy.wait_for_result()

        #Write Output to Log
        self.log.write("***** Proxy Output*****\n")
        self.log.write(ret.stderr_output)
        self.log.write("***********************\n")
        self.log.flush()
        self.log.write('[timer] Stop proxy: %f sec.\n' % (time.time() - ts))
        self.proxy_running = False
        return True

    def _stop_monitor(self, monitor):
        if self.monitor_running is False:
            return True
        ts = time.time()
        
        #Check whether monitor is still running
        if not monitor.is_running():
            print "Monitor has crashed!!!\n"
            self.log.write("Monitor has crashed!!!\n")
            self.log.flush()
            return False

        #Stop monitor
        monitor.send_signal(2)
        ret = monitor.wait_for_result()

        #Write Output to Log
        self.log.write("***** Monitor Output*****\n")
        self.log.write(ret.stderr_output)
        self.log.write("***********************\n")
        self.log.flush()
        self.log.write('[timer] Stop monitor: %f sec.\n' % (time.time() - ts))
        self.monitor_running = False
        return True

    def _cleanup(self):
        ts = time.time()

        #Kill Proxy
        shell = spur.SshShell(hostname = mv.vm2ip(self.tc[0]),username = config.vm_user,
                                  missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
        try:
            ret = shell.run(["/bin/bash", "-i", "-c", config.proxy_kill_cmd])
        except Exception as e:
            return False

        #Kill Monitor
        shell = spur.SshShell(hostname = mv.vm2ip(self.mon[0]),username = config.vm_user,
                                  missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
        try:
            ret = shell.run(["/bin/bash", "-i", "-c", config.monitor_kill_cmd])
        except Exception as e:
            return False
        self.log.write('[timer] Clean up: %f sec.\n' % (time.time() - ts))
        return True

    def _send_proxy_strategy(self, strategy):
        strat = ""
        # Default strategy
        if strategy == None:
            strategy = ["*,*,TCP,0,0,*,CLEAR,*","{0},{1},{2},0,0,*,CLEAR,*".format(config.target_client_ip, config.target_server_ip, config.protocol)]
        ts = time.time()

        for l in strategy:
            if type(l) is dict:
                if 'action' not in l:
                    return False
                strat = l['action']
                if 'time' in l and l['time'] > 0.01:
                    strat = dict(l)
                    strat['time'] = 0
                    tmr = threading.Timer(l['time'], self._send_proxy_strategy, [[strat],proxyaddrs])
                    tmr.start()
                    self.timers.append(tmr)
                    continue
            elif type(l) is str:
                strat = l
            else:
                return False
            self.log.write("Strategy CMD: " + strat + "\n")
            self.log.flush()
            for t in self.tc:
                res = self._proxy_communicate((mv.vm2ip(t), config.proxy_com_port), strat)
                if (res == False):
                    self.log.write("Failed to Send Command\n")
                    self.log.flush()
                    return False
        self.log.write('[timer] Send strategy: %f sec.\n' % (time.time() - ts))
        return True

    def _waitListening(self, host='127.0.0.1', port=80, timeout=None, output=False):
        """Wait until server is listening on port.
        returns True if server is listening"""
        cmd = ('echo A | telnet -e A %s %s' % (host, port))
        start = time.time()
        result = ""
        try:
            result = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            pass
        while 'Connected' not in result:
            if 'No route' in result:
                return False
            if timeout and time.time() >= start + timeout:
                print 'could not connect to %s on port %d' % (host, port)
                return False
            if output:
                print 'waiting for ' + host + ' to listen on port ' + str(port)
            time.sleep(0.5)
            try:
                result = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                pass
        if output:
            print host + " is listening on " + str(port)
            return True

    def _proxy_communicate(self, addr, msg, wait_for_response=False):
        rsp = ""

        # Connect
        try:
            sock = socket.create_connection(addr)
        except Exception as e:
            self.log.write(
                "Failed to connect to to proxy(%s:%d): %s\n" % (addr[0], addr[1], e))
            self.log.flush()
            return False

        # Buid command
        snd = struct.pack("!H", len(msg) + 2)
        snd += msg

        # Send command
        sock.send(snd)

        if wait_for_response:
            # Wait for Length
            data = ""
            while (len(data) < 3):
                try:
                    data = sock.recv(4, socket.MSG_PEEK)
                except Exception as e:
                    self.log.write("Recv failed: " + str(e) + "\n")
                    sock.close()
                    return False
                if len(data) == 0:
                    sock.close()
                    return False

            # compute length
            try:
                length = struct.unpack("!H", data[0:2])
                length = length[0]
            except Exception as e:
                sock.close()
                return False

            # Receive Message
            msg = ""
            mlen = length
            while(len(msg) < mlen):
                data = sock.recv(length)
                if len(data) == 0:
                    sock.close()
                    return False
                msg += data
                length -= len(data)

            # Process Message
            rsp = msg[2:]

        # Close Socket
        sock.close()
        if wait_for_response:
            return rsp
        return True

    def _start_capture(self):
        self.last_cap = ""
        if not self.do_capture:
            return None

        #Generate Capture Name
        time_str = time.strftime(config.captures_time_str)
        fname=config.captures_loc.format(tm=time_str,exe=self.instance)
        self.last_cap = fname

        #Generate capture command
        cmd = config.capture_cmd

        #Start SSH Shell
        shell = spur.SshShell(hostname = mv.vm2ip(self.tc[0]),username = config.vm_user,
                                  missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)

        #Start Capture
        cap = None
        try:
                cap = shell.spawn(["/bin/bash", "-i", "-c", cmd], store_pid=True, allow_error=True)
                if not cap.is_running():
                    res = proxy.wait_for_result()
                    self.log.write("Capture Failed to Start: " +  res.stderr_output)
                    return None
        except Exception as e:
            print e
            self.log.write("Exception: " + str(e) + "\n")
            self.log.flush()
            return None

        return cap


    def _stop_capture(self, cap):
        if not cap:
            return True

        ts = time.time()
        
        #Kill tcpdump
        shell = spur.SshShell(hostname = mv.vm2ip(self.tc[0]),username = config.vm_user,
                                  missing_host_key=spur.ssh.MissingHostKey.accept, private_key_file=config.vm_ssh_key)
        try:
                shell.run(["/bin/bash", "-i", "-c", config.capture_kill_cmd], allow_error=True)
        except Exception as e:
            pass
        cap.wait_for_result()

        if len(self.last_cap) > 0:
            os.system("scp -q -i %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s@%s:/root/capture.dmp %s\n" %
                        (config.vm_ssh_key, config.vm_user, mv.vm2ip(self.tc[0]), self.last_cap))

        self.log.write('[timer] Stop Capture: %f sec.\n' % (time.time() - ts))
        return True


    def _process_capture(self):
        f = PcapReader(self.last_cap)
   
        start_time = 0
        end_time = 0
        last_time = 0
        total_data = 0
        p = f.read_packet()
        while p != None:
            if p.haslayer(TCP) and p.haslayer(IP):
                if p[IP].src == config.target_server_ip or p[IP].dst == config.target_server_ip:
                    if p[TCP].flags & 0x2 > 0 and start_time < 10:
                        start_time = p.time
                    if (p[IP].len - p[IP].ihl*4 - p[TCP].dataofs*4) > 0:
                        total_data += (p[IP].len - p[IP].ihl*4 - p[TCP].dataofs*4)
                        if p.time - last_time < 1:
                            end_time = p.time
                        last_time = p.time
            p = f.read_packet()
        f.close()

        if start_time < 10 or end_time < 10:
            return False, 0, total_data
        return True, end_time - start_time, total_data


    def _compress_capture(self):
            os.system("gzip " + self.last_cap)
            self.last_cap += ".gz"

    def _query_proxy_conn_info(self):
        length = 0
        total_data = 0
        cmd = "{0},{1},{2},0,0,TIME,*".format(config.target_client_ip, config.target_server_ip,config.protocol)
        for t in self.tc:
            res = self._proxy_communicate((mv.vm2ip(t), config.proxy_com_port), cmd, wait_for_response=True)
            if type(res) is bool and res is False:
                return (False, 0, "System Error")
            if type(res) is not str:
                return (False, 0, "System Error")
            lns = res.split()
            if len(lns) != 2:
                return (False,0,"System Error")
            length = float(lns[0])
            total_data = int(lns[1])

        if length < 0 or length > 200:
            return False, length, total_data
        return True, length, total_data


    def _query_proxy_done(self):
        last = 0
        cmd = "*,*,{0},0,0,ACTIVE,*".format(config.protocol)
        for t in self.tc:
            res = self._proxy_communicate((mv.vm2ip(t), config.proxy_com_port), cmd, wait_for_response=True)
            if type(res) is bool and res is False:
                return False
            if type(res) is not str:
                return False
            last = float(res)
    
        if last < 10:
            return False

        if time.time() - last >= config.test_max_idle:
            return True
