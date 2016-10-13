//== core.h -----------------------------------------==//
//
//  Created on: Apr 27, 2016
//      Author: Endadul Hoque (mhoque@purdue.edu)
//==-------------------------------------------------------==//

#ifndef INCLUDE_SEARCHER_H_
#define INCLUDE_SEARCHER_H_

#include "graph.h"

typedef std::vector< std::pair<Node*, Edge*> > Path;

class Searcher {
  private:
    std::vector<Path> output_paths;
    Graph *graph;

    // Check if the action exists on the path
    bool existsAction(Path &p, Action &a);

    // It updates the member `paths`
    void scanForSinglePath(Node *u, Path &p, Action &a);

  public:
    Searcher(Graph *g);
    ~Searcher(){}

    bool findPaths(Action a);

    void printPaths();
    void printPaths(std::ostream &os);
    void printAbstractTestCases(std::string prefix);

    std::string toString(Path &p);
    std::string toStringPathConditions(Path &p);
};

extern int debug;


#endif /* INCLUDE_SEARCHER_H_ */
