#!/bin/env python
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
# Samuel Jero <sjero@purdue.edu>
# Utility to map from model paths to concrete test cases
import sys
import os
import re
import subprocess
from datetime import datetime
from types import NoneType


system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
state_searcher_path = os.path.abspath(os.path.join(system_home, 'state_searcher'))
config_path = os.path.abspath(os.path.join(system_home, 'config'))
sys.path.insert(0, config_path)
import config


class StateMapper():
    stateNameMap = {"SlowStart":"STATE_SLOW_START", "CongestionAvoidance":"STATE_CONG_AVOID", 
                        "FastRecovery":"STATE_FAST_RECOV", "ExponentialBackoff":"STATE_RTO"}
    actionMap = {
        #Send any ACK
        "ACK":[
                {'action':'FORCEACK','param':'amt=10&dir=2','type':'OnPath'},
                {'action':'FORCEACK','param':'amt=0&dir=2','type':'OnPath'},
                {'action':'PREACK','param':'method=3&amt=1','type':'OnPath'},
                {'action':'DIV','param':'bpc=100','type':'OnPath'},
                {'type':'OnPath'}
            ],
        #DUP Acks implemented with DUP action
        "ACK && dup":[
                {'action':'FORCEACK','param':'amt=0&dir=2','type':'OnPath'},
                {'action':'DUP','param':'num=100','type':'OnPath'},
                {'action':'DUP','param':'num=4','type':'OnPath'},
                {'action':'LIMITACK','param':'*','type':'OnPath'},
                {'type':'OnPath'}
            ],
        "ACK && dup && dupACKctr < 2":[
                {'action':'FORCEACK','param':'amt=0&dir=2','type':'OnPath'},
                {'action':'DUP','param':'num=1','type':'OnPath'}
            ],
        "ACK && dup && dupACKctr+1 == 3":[
                {'action':'DUP','param':'num=4','type':'OnPath'},
                {'action':'LIMITACK','param':'*','type':'OnPath'}
            ],
        #New Acks, heavily use PREACK and DIV
        "ACK && new":[
                {'action':'FORCEACK','param':'amt=10&dir=2','type':'OnPath'},
                {'action':'PREACK','param':'method=3&amt=1','type':'OnPath'},
                {'action':'DIV','param':'bpc=100','type':'OnPath'},
                {'type':'OnPath'}
            ],
        "ACK && new && cwnd + MSS >= ssthresh":[
                {'action':'PREACK','param':'method=3&amt=1','type':'OnPath'},
                {'action':'DIV','param':'bpc=100','type':'OnPath'},
                {'type':'OnPath'}
            ],
        "ACK && new && cwnd+MSS < ssthresh":[
                {'action':'FORCEACK','param':'amt=10&dir=2','type':'OnPath'},
                {'type':'OnPath'}
            ],
        "ACK && new && pkt.ack < high_water":[
                {'action':'DIV', 'param':'bpc=100','type':'OnPath'}
            ],
        "ACK && new && pkt.ack >= high_water":[
                {'action':'PREACK','param':'method=3&amt=1','type':'OnPath'},
                {'action':'DIV','param':'bpc=100','type':'OnPath'},
                {'type':'OnPath'}
            ],
        #BURST interrupts timing, making RTO likely. Also DROP packets and prevent new Acking
        "RTO Timeout":[
                {'action':'BURST','param':'num=10','type':'OnPath'},
                {'action':'DROP','param':'p=80','type':'OnPath'},
                {'action':'LIMITACK','param':'*','type':'OnPath'}
            ],
    }

    def __init__(self, lg, statemachinefile, searchterm):
        self.log = lg
        self.statemachinefname = statemachinefile
        self.searchterm = searchterm
        self.paths = []
        self.strategies = []

    def createStrategies(self):
        self._findPaths()
        self._convertPaths()
        return self.strategies

    def _findPaths(self):
        output = ""
        try:
            output = subprocess.check_output([state_searcher_path + "/bin/searcher", self.statemachinefname, self.searchterm])
        except Exception as e:
            print "[%s] Error: %s" %(str(datetime.today()),str(e))
            self.log.write("[%s] Error: Cannot run searcher: %s\n" % (str(datetime.today()),str(e)))
            self.paths = []
            return

        for line in output.split("\n"):
            if line.find("Found no paths") >= 0:
                print "[%s] Warning: No paths found in state machine" % (str(datetime.today()))
                self.log.write("[%s] Warning: No paths found in state machine\n" % (str(datetime.today())))
                self.paths = []
                return
            if line.find("Found paths") >= 0:
                continue
            if len(line) == 0:
                continue
            p = self._parsePath(line)
            self.paths.append(p)

    def _parsePath(self, ln):
        path = []
        for p in ln.split(";"):
            p = p.strip()
            mo = re.search("<([^,]+), \"([^\"]+)\">.*", p)
            if type(mo) is not NoneType:
                #print mo.group(1), ",",  mo.group(2)
                path.append([mo.group(1).strip(),mo.group(2).strip()])
        return path

    def _convertPaths(self):
        self.strategies = []
        for p in self.paths:
            components = {}
            for i in range(0, len(p)):
                state = self._mapState(p[i][0])
                actions,parameters,types = self._findAction(state, p[i][1])
                for j in range(0, len(actions)):
                    if types[j] not in components:
                        tmp = []
                        for q in range(0, len(p)):
                            tmp.append([])
                        components[types[j]] = tmp
                    components[types[j]][i].append(self._formatStrategy(state,actions[j],parameters[j]))
            for t in components.keys():
                self._buildStrats(components[t],0,[],t)

    def _buildStrats(self, states, i, strat, strat_type):
        if i >= len(states):
            if len(strat) > 0:
                self.strategies.append({'s':strat,'t':strat_type})
        else:
            for s in states[i]:
                if len(s) == 0:
                    self._buildStrats(states,i+1,strat,strat_type)
                else:
                    tmp = list(strat)
                    tmp.append(s)
                    self._buildStrats(states,i+1,tmp,strat_type)

    def _mapState(self, st):
        if st in StateMapper.stateNameMap:
            return StateMapper.stateNameMap[st]
        return st

    def _findAction(self, state, conditions):
        actions = []
        parameters = []
        types = []
        if conditions not in StateMapper.actionMap:
            print "[%s] Unknown Condition: %s" %(str(datetime.today()), conditions)
            self.log.write("[%s] Unknown Condition: %s\n" %(str(datetime.today()), conditions))
            return actions,parameters,types
        val = StateMapper.actionMap[conditions]
        for v in val:
            if "action" in v:
                actions.append(v["action"])
            else:
                actions.append("")
            if "param" in v:
                parameters.append(v["param"])
            else:
                parameters.append("")
            if "type" in v:
                types.append(v["type"])
            else:
                types.append("")
        return actions,parameters,types

    def _formatStrategy(self, state, action, parameters):
        if len(action) == 0:
            return ""
        s = "{src_ip},{dst_ip},{proto},{start},{end},{sstate},{saction},{sparam}".format(
                src_ip = config.target_client_ip, dst_ip = config.target_server_ip, 
                proto = config.protocol, start = str(0), end = str(0), sstate = state,
                saction = action, sparam = parameters)
        return s

if __name__ == "__main__":
    sm = StateMapper(sys.stdout, config_path + "/tcp-newreno.xml", "cwnd")
    strats = sm.createStrategies()
    print strats
    print len(strats)
