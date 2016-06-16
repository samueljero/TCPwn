#Samuel Jero <sjero@purdue.edu>
#CC Testing Strategy Generation
import os
import sys
import time
from datetime import datetime
import re
import pprint
from types import NoneType
import manipulations
from email.mime.text import MIMEText
import smtplib

system_home = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
config_path = os.path.abspath(os.path.join(system_home, 'config'))
sys.path.insert(0,config_path)
import config

class StrategyGenerator:
	#Constructor
	def __init__(self, lg, res_lg):
		self.lg = lg
		self.results = res_lg
		self.ck_file = None
		self.do_ckpt = False

		self.strat_lst = []
                self.proc_lst = []
		self.failed_lst = []
                self.strat_num = 0


	def next_strategy(self):
		# Check for new failed strategies that need to be retried
		if len(self.failed_lst) > 0:
			strat = self.failed_lst.pop()
			return strat

		#Check if all strategies have been tested
		if len(self.strat_lst) is 0:
			return None

		#Select next strategy
		strat = self.strat_lst.pop(0)
                self.proc_lst.append(strat)

                self.strat_num += 1
		if self.strat_num % 10 == 0:
			self.lg.write("[%s] Returning Strategy: %d/%d\n" % (str(datetime.today()),self.strat_num, len(self.strat_lst)+len(self.proc_lst)))
			print "[%s] Testing Strategy: %d/%d" % (str(datetime.today()),self.strat_num, len(self.strat_lst)+len(self.proc_lst))
                if self.strat_num % 100 == 0:
			self.checkpoint()
		return strat

	def return_strategy(self, strat):
		self.failed_lst.append(strat)

	def strategy_result(self, strat, result, reason, feedback):
		if result == False:
                        if reason == "System Failure":
                            self._send_warning_email(strat)
                        strat['retries']+= 1
			if strat['retries'] <= config.failed_retries:
                                self.lg.write("[%s] Strategy will be retried: %s\n" % (str(datetime.today()),str(strat)))
				self.failed_lst.append(strat)
			else:
				#Final failure, record in result file
				lst = ["FAILED", str(datetime.today()),strat, reason, feedback['capture']]
				self.results.write("%s\n" %(str(lst)))
				self.results.flush()
				self.lg.write("[%s] Strategy HARD FAILED: %s\n" % (str(datetime.today()),str(strat)))
				print "[%s] Strategy HARD FAILED: %s" % (str(datetime.today()),str(strat))
		else:
			#Test Succeeded
                        pass

	def strategy_feedback(self, strat, feedback, result = None):
		if type(feedback)!=dict:
			return
                return

	def build_strategies(self):
                src_ip = "10.0.3.1"
                dst_ip = "10.0.3.3"
                proto = "TCP"

                #Single Action strategies
                for action,template,params,ignore in manipulations.selfish_receiver_actions:
                    for p in params:
                        s = {'strat':[self._create_strat(src_ip,dst_ip,proto,0,0,action,template,p)], 'priority':0, 'retries':0}
                        self.strat_lst.append(s)
                        for length in manipulations.length_full:
                            for start in manipulations.start_full:
                                s = {'strat':[self._create_strat(src_ip,dst_ip,proto,start,start+length,action,template,p)], 'priority':0, 'retries':0}
                                self.strat_lst.append(s)

                #Combinations of two
                for a_start in manipulations.chunk_start:
                    for b_start in manipulations.chunk_start:
                        for a_action,a_template,a_ignore,a_params in manipulations.selfish_receiver_actions:
                            for b_action,b_template,b_ignore,b_params in manipulations.selfish_receiver_actions:
                                if not self._actions_compatible(a_action,b_action,a_start,b_start):
                                    continue
                                for a_p in a_params:
                                    for b_p in b_params:
                                        s = {'strat':[ self._create_strat(src_ip,dst_ip,proto,a_start,a_start+manipulations.chunk_len,a_action,a_template,a_p),
                                                       self._create_strat(src_ip,dst_ip,proto,b_start,b_start+manipulations.chunk_len,b_action,b_template,b_p)],
                                             'priority':0, 'retries':0}
                                        self.strat_lst.append(s)
		
                self.lg.write("[%s] Strategies: %d\n" % (str(datetime.today()),len(self.strat_lst)))
		print "[%s] Strategies: %d" % (str(datetime.today()),len(self.strat_lst))


        def _create_strat(self, src_ip, dst_ip, proto, start, end, action, p_template, p_arg):
            args = p_template.format(p_arg)
            strat = "%s,%s,%s,%d,%d,%s,%s" % (src_ip, dst_ip, proto, start, end, action, args)
            return strat

        def _actions_compatible(self,action_a, action_b, start_a, start_b):
            if action_a == action_b:
                return False
            if start_a == start_b:
                if action_a in ["DIV", "DUP", "BURST"] and action_b in ["DIV", "DUP", "BURST"]:
                    return False
                if action_a in ["PREACK", "RENEGE"] and action_b in ["PREACK", "RENEGE"]:
                    return False
            return True

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
		self.ck_file = f
		self.do_ckpt = True
		self.checkpoint()

	def checkpoint(self):
		if self.do_ckpt and self.ck_file is not None:
			self.lg.write("[%s] Making Checkpoint\n" % (str(datetime.today())))
			print "[%s] Making Checkpoint" % (str(datetime.today()))

			#Create backup
			bkup = {}
			bkup['version'] = 0
			bkup['strat_lst'] = self.strat_lst
			bkup['proc_lst'] = self.proc_lst
			bkup['failed_lst'] = self.failed_lst
                        bkup['strat_num'] = self.strat_num

                        #Format
                        pp = pprint.PrettyPrinter()
                        fmtbkup = pp.pformat(bkup)

			#Write backup
			try:
				self.ck_file.seek(0)
				self.ck_file.truncate()
				self.ck_file.write(fmtbkup)
				self.ck_file.flush()
			except Exception as e:
				print "[%s] Checkpoint Failed: %s" % (str(datetime.today()),str(e))
				return
			self.lg.write("[%s] Checkpoint Finished\n" % (str(datetime.today())))
			print "[%s] Checkpoint Finished" % (str(datetime.today()))

	def restore(self, f):
		#Read backup
		try:
			inp = f.readlines()
                        inp = "\n".join(inp)
			bkup = eval(inp)
		except Exception as e:
			print "[%s] Failed to read checkpoint: %s" % (str(datetime.today()),str(e))
			f.close()
			return False

		#Restore Backup
		if bkup['version'] != 0:
			print "Warning: Checkpoint is incompatable!!!"
			f.close()
			return False
		self.strat_lst = bkup['strat_lst']
                self.proc_lst = bkup['proc_lst']
		self.strat_num = bkup['strat_num']
		self.failed_lst = bkup['failed_lst']

		f.close()
		self.lg.write("[%s] Restore Finished\n" % (str(datetime.today())))
		print "[%s] Restore Finished" % (str(datetime.today()))
		return True

	def load_from_file(self, f):
		strat = None
		for line in f:
			if line.find("#") >= 0:
				continue
			strat = eval(line)
			self.strat_lst.append(strat)

