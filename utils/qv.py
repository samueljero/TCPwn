#!/bin/env python
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
# Samuel Jero <sjero@purdue.edu>
# Quick Results viewer
import sys
import os
import re
import argparse
import pprint


def main(args):
        pp = pprint.PrettyPrinter()

        #Parse Args
        argp = argparse.ArgumentParser(description='Quick Results Viewer')
        argp.add_argument('out_file', help="Output File")
        args = vars(argp.parse_args(args[1:]))

        #Open Results file
        resultfile = None
        try:    
                resultfile = open(args['out_file'], "r")
        except Exception as e:
                print "Error: could not open %s" % (args['out_file'])
                sys.exit(1)

        for line in resultfile:
            line = line.strip()
            if line[0] == "#":
                print line
                continue

            result = None
            try:
                    result = eval(line)
            except Exception as e:
                    print e
                    continue

            if type(result) is not dict:
                print result

            strat = ""
            timestamp = ""
            testresult = ""
            byte = ""
            time = ""
            typ = ""

            if 'strat' in result:
                rawstrat = result['strat']
                if 'strat' in rawstrat:
                    strat = rawstrat['strat']
                else:
                    strat = rawstrat
                if 'type' in rawstrat:
                    typ = rawstrat['type']
            if 'date' in result:
                timestamp = result['date']
            if 'reason' in result:
                testresult = result['reason']
            if 'bytes' in result:
                byte = result['bytes']
            if 'time' in result:
                time = result['time']


            lst = [timestamp,testresult,typ,strat,time,byte]
            print pp.pformat(lst)


        return 0


if __name__ == "__main__":
        main(sys.argv)
