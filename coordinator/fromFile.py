# Samuel Jero <sjero@purdue.edu>
# CC Testing Strategy Generation
# Strategies from File
from strategyGenerator import StrategyGenerator
import os
import sys
from datetime import datetime
from types import NoneType
from email.mime.text import MIMEText
import smtplib

system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
config_path = os.path.abspath(os.path.join(system_home, 'config'))
sys.path.insert(0, config_path)
import config


class FromFile(StrategyGenerator):
        # Constructor

        def __init__(self, lg, res_lg, f):
                self.lg = lg
                self.results = res_lg
                self.strat_lst = []
                self.proc_lst = []
                self.failed_lst = []
                self.strat_num = 0
                self.stratFile = f

        def next_strategy(self):
                # Check for new failed strategies that need to be retried
                if len(self.failed_lst) > 0:
                        strat = self.failed_lst.pop()
                        return strat

                # Check if all strategies have been tested
                if len(self.strat_lst) is 0:
                        return None

                # Select next strategy
                strat = self.strat_lst.pop(0)
                self.proc_lst.append(strat)

                self.strat_num += 1
                if self.strat_num % 10 == 0:
                        self.lg.write("[%s] Returning Strategy: %d/%d\n" % (str(datetime.today()), self.strat_num, len(self.strat_lst) + len(self.proc_lst)))
                        print "[%s] Testing Strategy: %d/%d" % (str(datetime.today()), self.strat_num, len(self.strat_lst) + len(self.proc_lst))
                if self.strat_num % 100 == 0:
                        self.checkpoint()
                return strat

        def return_strategy(self, strat):
                self.failed_lst.append(strat)

        def strategy_result(self, strat, result, reason, feedback):
            if result == False:
                       if reason == "System Failure":
                                self._send_warning_email(strat)
                       strat['retries'] += 1
                       if strat['retries'] <= config.failed_retries:
                                self.lg.write("[%s] Strategy will be retried: %s\n" % (str(datetime.today()), str(strat)))
                                self.failed_lst.append(strat)
                       else:
                                # Final failure, record in result file
                                lst = ["FAILED", str(datetime.today()), strat, reason, feedback['capture'], feedback['last']]
                                self.results.write("%s\n" % (str(lst)))
                                self.results.flush()
                                self.lg.write("[%s] Strategy HARD FAILED: %s\n" % (str(datetime.today()), str(strat)))
                                print "[%s] Strategy HARD FAILED: %s" % (str(datetime.today()), str(strat))
            else:
                      # Test Succeeded
                      pass

        def strategy_feedback(self, strat, feedback, result=None):
                return

        def build_strategies(self):
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

        def _send_warning_email(self, strat):
                if not config.email_on_system_fail:
                       return
                msg = """Administrator,
This message is to notify you that a strategy being tested by the Congestion Control
testing system has failed and indicated that it was a System Failure. The strategy was:
"""
                msg += str(strat)
                msg += """


The CC Testing System
        """
                msg = MIMEText(msg)
                msg["Subject"] = "CC Testing: System Failure"
                msg["From"] = config.src_email_address
                msg["To"] = config.dst_email_address

                s = smtplib.SMTP("localhost")
                s.sendmail(config.src_email_address, [config.dst_email_address], msg.as_string())
                s.quit()
                return

        def enable_checkpointing(self, f):
                return

        def checkpoint(self):
                return

        def restore(self, f):
                return False
                

