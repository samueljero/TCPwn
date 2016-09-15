#!/bin/env python
# Samuel Jero <sjero@purdue.edu>
# Timing Graph Generator
import sys
import os
from os import listdir
from os.path import isfile, isdir, join, split, abspath, exists
import re
import argparse
from types import NoneType

prior_choice = None
prior_log_choice = "yes"
prior_capture_choice = "yes"
prior_term_choice = "yes"
prior_raw_choice = "yes"
prior_categorize_choice = "yes"
term_type = ""
opt_break = True

#https://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

def main(args):
	global term_type

	#Parse Args
	argp = argparse.ArgumentParser(description='Timing Graph Generator')
	argp.add_argument('log_file', help="Input Logfile")
	argp.add_argument('out_file', help="Output File")
	args = vars(argp.parse_args(args[1:]))

	
	#Open log file
	logfile = None
	try:	
		logfile = open(args['log_file'],"r")
	except Exception as e:
		print "Error: could not open " + args['log_file']
		sys.exit(1)

	#Open Output File
	try:
		outfile = open(args['out_file'], "w")
	except Exception as e:
		print "Error: could not open output file"
		sys.exit(1)

	# Read Results file
        thresholds = False
        name = ""
        for line in logfile:
            if line.find("Strategy CMD:") >= 0:
                parts = line.split(":")
                nm = parts[1].strip()
                parts = nm.split(",")
                nm = ",".join(parts[3:])
                if len(name) > 0:
                    name += ":"
                name += nm
            elif line.find("Performance:") >= 0:
                parts = line.split(":")
                if len(name) > 0:
                    outfile.write("%s\t%s\n" %(name, str(float(parts[1].strip()))))
                    #print name, float(parts[1].strip())
                    name = ""
            elif line.find("################") >= 0:
                name = ""
            elif line.find("$$$$$$$$$$$$$$$$") >= 0:
                thresholds = not thresholds
            elif thresholds:
                outfile.write("#" + line)
            

        logfile.close()
	outfile.close()
	return 0


if __name__ == "__main__":
	main(sys.argv)
