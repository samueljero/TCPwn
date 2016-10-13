# Samuel Jero <sjero@purdue.edu>
# CC Testing Strategy Generation
# State Machine Based Algorithm
from strategyGenerator import StrategyGenerator
import os
import sys
from datetime import datetime
import manipulations

system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
config_path = os.path.abspath(os.path.join(system_home, 'config'))
state_searcher_path = os.path.abspath(os.path.join(system_home, 'state_searcher'))
sys.path.insert(0, config_path)
import config

class StateBased(StrategyGenerator):
    # Constructor
    def __init__(self, lg, res_lg):
        StrategyGenerator.__init__(self,lg,res_lg)

    def build_strategies(self):
        src_ip = config.target_client_ip
        dst_ip = config.target_server_ip
        proto = config.protocol

        #Do Stuff

        self.lg.write("[%s] Strategies: %d\n" % (str(datetime.today()), len(self.strat_lst)))
        print "[%s] Strategies: %d" % (str(datetime.today()), len(self.strat_lst))

    def _create_strat(self, src_ip, dst_ip, proto, start, end, state, action, p_template, p_arg):
        args = p_template.format(p_arg)
        strat = "%s,%s,%s,%d,%d,%s,%s,%s" % (src_ip, dst_ip, proto, start, end, state, action, args)
        return strat

