# Samuel Jero <sjero@purdue.edu>
# CC Testing Strategy Generation
# State Machine Based Algorithm
from strategyGenerator import StrategyGenerator
import os
import sys
from datetime import datetime
import manipulations
from statemapper import StateMapper 

system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
config_path = os.path.abspath(os.path.join(system_home, 'config'))
state_searcher_path = os.path.abspath(os.path.join(system_home, 'state_searcher'))
sys.path.insert(0, config_path)
import config

class StateBased(StrategyGenerator):
    # Constructor
    def __init__(self, lg, res_lg):
        StrategyGenerator.__init__(self,lg,res_lg)
        self.sm = StateMapper(lg, config.coord_strategy_generation_state_machine_file, 
                    config.coord_strategy_generation_state_machine_search)

    def build_strategies(self):
        self.strat_lst = self.sm.createStrategies()
        self.lg.write("[%s] Strategies: %d\n" % (str(datetime.today()), len(self.strat_lst)))
        print "[%s] Strategies: %d" % (str(datetime.today()), len(self.strat_lst))
