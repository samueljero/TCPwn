/******************************************************************************
* Author: Endadul Hoque <mhoque@purdue.edu> and  Samuel Jero <sjero@purdue.edu>
* State Machine Path Searcher: Main
******************************************************************************/
#include <iostream>
#include <cstdio>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstring>

//--- For creating new directory ---
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "graph.h"
#include "searcher.h"
using namespace std;

#define VERSION 0.1
#define COPYRIGHT_YEAR 2016

void version();
void printUsage(const char *prog);


int main(int argc, char *argv[]){
  string outdir = "";
  string outfileprefix = "path";
  string xmlfile, action;
  struct stat st = {0};
  int optind;

  /* Commandline Args */
  for (optind = 1; optind < argc && argv[optind][0] == '-'; optind++) {
      switch (argv[optind][1]) {
        case 'd':
          optind++;
          if(argv[optind]){
            outdir = argv[optind];
          }
          else{
            cerr << "Argument error" << endl;
            printUsage(argv[0]);
          }
          break;
        case 'o':
          optind++;
          if(argv[optind]){
            outfileprefix = argv[optind];
          }
          else{
            cerr << "Argument error" << endl;
            printUsage(argv[0]);
          }
          break;
        case 'v':
          debug++;
	  break;
        case 'V':
          version();
          break;
        default:
          printUsage(argv[0]);
      }
  }
  if(argv[optind] == NULL){
    cerr << "Argument error" << endl;
    printUsage(argv[0]);
  }
  xmlfile = argv[optind++];

  if(argv[optind] == NULL){
    cerr << "Argument error" << endl;
    printUsage(argv[0]);
  }
  action = argv[optind++];

  /* Create Graph */
  Graph graph(xmlfile);
  if (debug > 2) {
    graph.printGraph();
  }
  Searcher searcher(&graph);

  /* Look for paths */
  if(searcher.findPaths(action)){
    cout << "Found paths" << endl;

    /*Print paths */
    searcher.printPaths();

    /* Output, if we have a directory to output to */
    if (outdir.length() > 0) {
      if (stat(outdir.c_str(), &st) == -1) {
          if(mkdir(outdir.c_str(), 0700)){
            cerr << "Failed to create directory: " << outdir << endl;
            exit(EXIT_FAILURE);
          }
      }

      /* Output paths */
      stringstream ss;
      ss << outdir << "/" << outfileprefix;
      outfileprefix = ss.str();
      searcher.printAbstractTestCases(outfileprefix);
    }
  }
  else{
    cout << "Found no paths" << endl;
  }
  return 0;
}

void version()
{
	cerr << "Searcher version " << VERSION << endl;
	cerr << "Copyright (C) " << COPYRIGHT_YEAR << " Endadul Hoque <mhoque@purdue.edu> and Samuel Jero <sjero@purdue.edu>" << endl;
	exit(0);
}

void printUsage(const char *prog){
  cerr << "Usage: " << prog << " [Options] input-model-file \"action to find\"" << endl;
  cerr << "Options are:" << endl;
  cerr << "     -o FILE_PREFIX    The output file prefix (default: path)" << endl;
  cerr << "     -d OUTPUT_DIR     Output directory (default: None)" << endl;
  cerr << "     -h                Display this usage message" << endl;
  cerr << "     -V                Print Version Info" << endl;
  cerr << "     -v                verbose. May be repeated for additional verbosity." << endl;
  exit(EXIT_FAILURE);
}
