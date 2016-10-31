# Samuel Jero <sjero@purdue.edu>
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
# CC Testing Strategy Generation
# Simple Brute Force and From File algorithms
from strategyGenerator import StrategyGenerator
import os
import sys
from datetime import datetime
import manipulations
from stateMapper import StateMapper

system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
config_path = os.path.abspath(os.path.join(system_home, 'config'))
sys.path.insert(0, config_path)
import config


class BruteForce(StrategyGenerator):
    # Constructor
    def __init__(self, lg, res_lg):
        StrategyGenerator.__init__(self,lg,res_lg)

    def build_strategies(self):
        src_ip = config.target_client_ip
        dst_ip = config.target_server_ip
        proto = config.protocol

        # Single Action strategies
        for action, template, params, ignore in manipulations.selfish_receiver_actions:
            for p in params:
                s = {'strat': [self._create_strat(src_ip, dst_ip, proto, 0, 0, "*", action, template, p)], 'priority': 0, 'retries': 0}
                self.strat_lst.append(s)
                for length in manipulations.length_full:
                    for start in manipulations.start_full:
                        s = {'strat': [self._create_strat(src_ip, dst_ip, proto, start, start + length, "*", action, template, p)], 'priority': 0, 'retries': 0, 'type':'OnPath'}
                        self.strat_lst.append(s)

        # Combinations of two
        for a_start in manipulations.chunk_start:
            for b_start in manipulations.chunk_start:
                for a_action, a_template, a_ignore, a_params in manipulations.selfish_receiver_actions:
                    for b_action, b_template, b_ignore, b_params in manipulations.selfish_receiver_actions:
                        if not self._actions_compatible(a_action, b_action, a_start, b_start):
                            continue
                        for a_p in a_params:
                            for b_p in b_params:
                                s = {'strat': [self._create_strat(src_ip, dst_ip, proto, a_start, a_start + manipulations.chunk_len, "*", a_action, a_template, a_p),
                                               self._create_strat(src_ip, dst_ip, proto, b_start, b_start + manipulations.chunk_len, "*", b_action, b_template, b_p)],
                                     'priority': 0, 'retries': 0, 'type':'OnPath'}
                                self.strat_lst.append(s)

        self.lg.write("[%s] Strategies: %d\n" % (str(datetime.today()), len(self.strat_lst)))
        print "[%s] Strategies: %d" % (str(datetime.today()), len(self.strat_lst))

    def _create_strat(self, src_ip, dst_ip, proto, start, end, state, action, p_template, p_arg):
        args = p_template.format(p_arg)
        strat = "%s,%s,%s,%d,%d,%s,%s,%s" % (src_ip, dst_ip, proto, start, end, state, action, args)
        return strat

    def _actions_compatible(self, action_a, action_b, start_a, start_b):
        if action_a == action_b:
            return False
        if start_a == start_b:
            if action_a in ["DIV", "DUP", "BURST"] and action_b in ["DIV", "DUP", "BURST"]:
                return False
            if action_a in ["PREACK", "RENEGE"] and action_b in ["PREACK", "RENEGE"]:
                return False
        return True


class FromFile(StrategyGenerator):
    # Constructor
    def __init__(self, lg, res_lg, f):
            StrategyGenerator.__init__(self, lg, res_lg)
            self.stratFile = f

    def build_strategies(self):
            print "Loading Strategies from File..."
            self.lg.write("[%s] Loading Strategies from File\n" % (str(datetime.today())))
            strat = None
            if self.strat_file is None:
                    return
            for line in self.strat_file:
                    if line.find("#") >= 0:
                            continue
                    strat = eval(line)
                    self.strat_lst.append(strat)
            self.strat_file.close()
            self.strat_file = None
            self.lg.write("[%s] Strategies: %d\n" % (str(datetime.today()), len(self.strat_lst)))
            print "[%s] Strategies: %d" % (str(datetime.today()), len(self.strat_lst))


class StateBased(StrategyGenerator):
    # Constructor
    def __init__(self, lg, res_lg):
        StrategyGenerator.__init__(self,lg,res_lg)
        self.sm = StateMapper(lg, config.coord_strategy_generation_state_machine_file,
                    config.coord_strategy_generation_state_machine_search)

    def build_strategies(self):
        strategies = self.sm.createStrategies()
        for s in strategies:
            if s['t'] != 'OnPath':
                continue
            d = {'strat':s['s'], 'priority':0, 'retries':0, 'type':s['t']}
            self.strat_lst.append(d)
        self.lg.write("[%s] Strategies: %d\n" % (str(datetime.today()), len(self.strat_lst)))
        print "[%s] Strategies: %d" % (str(datetime.today()), len(self.strat_lst))
