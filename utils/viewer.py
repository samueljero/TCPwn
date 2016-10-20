#!/bin/env python
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
# Samuel Jero <sjero@purdue.edu>
# Results viewer
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

#https://stackoverflow.com/questions/3041986/python-command-line-yes-no-input
def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).
    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

def query_next():
        global prior_choice, opt_break
        valid = {"next":'n', "n": 'n', "ne":'n', "nex":'n',
                        }
        while True:
                sys.stdout.write("Option: [n/p/s/j/g/b/q] ")
                choice = raw_input().lower()
                if prior_choice is not None and choice == '':
                        return prior_choice
                elif choice == "next" or choice == "n":
                        prior_choice = ("n",0)
                        return ("n",0)
                elif choice == "previous" or choice == "p":
                        prior_choice = ("p",0)
                        return ("p", 0)
                elif choice == "same" or choice == "s":
                        prior_choice = ("s", 0)
                        return ("s",0)
                elif choice.find("jump") >= 0:
                        mo = re.search("jump (\-0-9]+)", choice)
                        if type(mo) is not NoneType:
                                prior_choice = ("j", int(mo.group(1)))
                                return ("j", int(mo.group(1)))
                elif choice.find("j") >= 0:
                        mo = re.search("j ([\-0-9]+)", choice)
                        if type(mo) is not NoneType:
                                prior_choice = ("j", int(mo.group(1)))
                                return ("j", int(mo.group(1)))
                elif choice.find("goto") >= 0:
                        mo = re.search("goto ([0-9]+)", choice)
                        if type(mo) is not NoneType:
                                prior_choice = ("g", int(mo.group(1)))
                                return ("g", int(mo.group(1)))
                elif choice.find("g") >= 0:
                        mo = re.search("g ([0-9]+)", choice)
                        if type(mo) is not NoneType:
                                prior_choice = ("g", int(mo.group(1)))
                                return ("g", int(mo.group(1)))
                elif choice == "quit" or choice == "q":
                        return ("q",0)
                elif choice == "break" or choice == "b":
                        opt_break = not opt_break
                        if opt_break:
                                print "Efficiency Break On"
                        else:
                                print "Efficiency Break Off"
                else:
                        sys.stdout.write("Invalid Response. Try Again.\n")

def handle_strat(result, ln_no, executor_files, capture_directory, out):
        global prior_log_choice, prior_capture_choice, prior_term_choice, prior_raw_choice, prior_categorize_choice, term_type, opt_break
        res = "?"
        time = "?"
        strat = "?"
        reason = "?"
        cap = ""
        ttm = None
        tb = None

        #Components
        if 'result' in result:
            res = result['result']
        if 'date' in result:
            time = result['date']
        if 'strat' in result:
            strat = result['strat']['strat']
        if 'reason' in result:
            reason = result['reason']
        if 'capture' in result:
            cap = result['capture']
        if 'time' in result:
            ttm = result['time']
        if 'bytes' in result:
            tb = result['bytes']

        #Output
        print "\n\n\n\n"
        print "Num: " + str(ln_no)
        for s in strat:
                print "Strategy: " + s
        print "Time: " + time
        print "Result: " + res
        print "Reason: " + reason
        if ttm is not None:
            print "Transfer Time: " + str(ttm)
        if tb is not None:
            print "Transfer Bytes: " + str(tb)

        #View Log
        if query_yes_no("View Log?", prior_log_choice):
                prior_log_choice = "yes"
                found = 0
                for fname in executor_files:
                        lnum = 0
                        with open(fname, "r") as f:
                                for line in f:
                                        lnum += 1
                                        if line.find(str(strat)) > 0:
                                                os.system(term_type + " -e 'vim +{0} -R {1}'".format(str(lnum), fname))
                                                found += 1
                                        if found >= 2:
                                                if opt_break:
                                                        break
                                                else:
                                                        if query_yes_no("More?", "no"):
                                                                found = 0
                                                        else:
                                                                break
        else:
                prior_log_choice = "no"

        #View Capture
        if query_yes_no("View Capture?", prior_capture_choice):
                prior_capture_choice = "yes"
                fname = abspath(join(capture_directory,split(cap)[1]))
                print "File: " + fname
                if query_yes_no("Open Terminal?", prior_term_choice):
                        prior_term_choice = "yes"
                        if not exists("/tmp/cc_examine"):
                                os.system("mkdir /tmp/cc_examine")
                        print "Capture file name is available in $FILE"
                        os.system(term_type + " -e '/bin/bash -c \"cd /tmp/cc_examine; export FILE='" + fname + "'; bash\"'")
                else:
                        prior_term_choice = "no"
        else:
                prior_capture_choice = "no"

        #View Raw Strategy
        if query_yes_no("View Raw?", prior_raw_choice):
                prior_raw_choice = "yes"
                print strat
        else:
                prior_raw_choice = "no"

        #Output
        if query_yes_no("Categorize?", prior_categorize_choice):
                prior_categorize_choice = "yes"
                cat = raw_input("Category: ").strip().upper()
                details = raw_input("Details: ").strip()
                info = []
                info.append(cat)
                info.append(result[1])
                info.append(result[2])
                info.append(result[3])
                info.append(split(cap)[1])
                info.append(details)
                out.write(repr(info))
                out.flush()
        else:
                prior_categorize_choice = "no"
        return

def main(args):
        global term_type

        #Parse Args
        argp = argparse.ArgumentParser(description='Testing Results Viewer')
        argp.add_argument('logs', help="Log directory")
        argp.add_argument('captures', help="Captures directory")
        argp.add_argument('out_file', help="Categorized Output File")
        args = vars(argp.parse_args(args[1:]))

        #Find Available Terminal
        if which("gnome-terminal") is not None:
                term_type = "gnome-terminal"
        elif which("mate-terminal") is not None:
                term_type = "mate-terminal"
        elif which("xterm") is not None:
                term_type = "xterm"
        else:
                print "No Supported Terminal Available"
                term_type = ""

        #Open Results file
        resultfile = None
        try:
                resultfile = open(join(args['logs'],"results.log"), "r")
        except Exception as e:
                print "Error: could not open results.log. Not a log directory."
                sys.exit(1)

        #Find Executor files
        onlyfiles = [ f for f in listdir(args['logs']) if isfile(join(args['logs'],f)) ]
        instfiles = []
        for f in onlyfiles:
                mo = re.search("inst[0-9]+\.log", f)
                if type(mo) is not NoneType:
                        instfiles.append(join(args['logs'],f))

        #Check Captures directory
        if not isdir(args['captures']):
                print "Error: %s is not a directory" % args['captures']
                sys.exit()
        capturedirectory = args['captures']


        #Open Output File
        try:
                outfile = open(args['out_file'], "a")
        except Exception as e:
                print "Error: could not open output file"
                sys.exit(1)

        # Read Results file
        flines = resultfile.readlines()
        resultfile.close()
        i = 0
        fmt = ""

        #Loop over results
        while i < len(flines):
                if flines[i][0] == "#":
                        i += 1
                        continue
                try:
                        result = eval(flines[i])
                except Exception as e:
                        print e
                        i += 1
                        continue

                if type(result) is list:
                    result = handleList(result)

                if type(result) is not dict:
                    i+=1
                    continue

                handle_strat(result, i, instfiles, capturedirectory, outfile)

                r = query_next()
                if r[0] == "n":
                        i+=1
                elif r[0] == "p":
                        i-=1
                elif r[0] == "s":
                        i = i
                elif r[0] == "j":
                        i = i + r[1]
                        if (i < 0):
                                i = 0
                elif r[0] == "g":
                        i = r[1]
                elif r[0] == "q":
                        break

        outfile.close()
        return 0

def handleList(lst):
    if len(lst) < 5:
        return None
    res = lst[0]
    time = lst[1]
    strat = lst[2]
    reason = lst[3]
    cap = lst[4]
    d = {'result':res, 'date':time, 'strat':strat,'reason':reason,'capture':cap}

    if len(lst) >= 6:
        d['time'] = lst[5]
    if len(lst) >= 7:
        d['bytes'] = lst[6]
    return d

if __name__ == "__main__":
        main(sys.argv)
