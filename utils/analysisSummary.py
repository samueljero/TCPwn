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
        argp = argparse.ArgumentParser(description='Analysis Summary')
        argp.add_argument('out_file', help="Analysis File")
        args = vars(argp.parse_args(args[1:]))

        #Open Results file
        resultfile = None
        try:    
                resultfile = open(args['out_file'], "r")
        except Exception as e:
                print "Error: could not open %s" % (args['out_file'])
                sys.exit(1)


        true_strats = 0
        false_strats = 0
        opt_ack = 0
        desync = 0
        ack_lost_data = 0

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

            category = ""
            strat = ""
            details = ""
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
            if 'reason' in result:
                testresult = result['reason']
            if 'bytes' in result:
                byte = result['bytes']
            if 'time' in result:
                time = result['time']
            if 'category' in result:
                category = result['category']
            if 'details' in result:
                details = result['details']


            if "TRUE" in category:
                true_strats+=1
            if "FALSE" in category:
                false_strats+=1
            if "Desync" in details:
                desync+=1
            if "Increment in SS" in details:
                ack_lost_data += 1
            if "Increment in FR" in details:
                ack_lost_data +=1
            if "Acking data above loss in FR" in details:
                ack_lost_data +=1
            if "Optimistic Ack" in details or "Opt Ack" in details and not typ is "OffPath":
                opt_ack +=1


        print "True Strategies: " + str(true_strats)
        print "False Strategies: " + str(false_strats)
        print "Desync: " + str(desync)
        print "Ack Lost Data: " + str(ack_lost_data)
        print "Optimistic Ack: " + str(opt_ack)

        return 0


if __name__ == "__main__":
        main(sys.argv)
