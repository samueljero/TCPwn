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
        argp = argparse.ArgumentParser(description='Formatted viewer')
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

            print pp.pformat(result)
            print ""


        return 0


if __name__ == "__main__":
        main(sys.argv)
