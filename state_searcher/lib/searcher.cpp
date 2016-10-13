//== searcher.cpp -----------------------------------------==//
//
//  Created on: Apr 27, 2016
//      Author: Endadul Hoque (mhoque@purdue.edu)
//==-------------------------------------------------------==//
#include "searcher.h"
#include "config.h"
#define ENABLE_DEBUG
#include <fstream>
#include <sstream>
#include <algorithm>
using namespace std;

int debug = 1;

Searcher::Searcher(Graph *g){
  FANCY_ASSERT("Graph can't be NULL", g);
  graph = g;
}

bool Searcher::existsAction(Path& p, Action &action) {
  for(Path::iterator it = p.begin(), et = p.end(); it != et; ++it){
    FANCY_ASSERT("Node can't be null", it->first != NULL);

    // check the list of action of this edge
    if(it->second){
      Edge *edge = it->second;
      if(edge->containsAction(action)){
        return true;
      }
    }
  }
  return false;
}

string Searcher::toString(Path &p){
  stringstream ss;
  Node *cycle_start = NULL;
  bool hasCycle = false;

  // Find if the path has a cycle
  Path::reverse_iterator last_elem = p.rbegin();
  if(last_elem->second){
    cycle_start = last_elem->first->getEndNode(last_elem->second);
    if(cycle_start){
      hasCycle = true;
    }
  }

  for(Path::iterator it = p.begin(), et = p.end(); it != et; ){
    if(hasCycle){
      if(it->first == cycle_start){
        ss << "[";
      }
    }
    ss << "<" << it->first->name << ", \"" << it->second->toStringEdgeConditions() << "\">";
    ++it;
    if(it != et){
      ss << " ; ";
    }
  }
  if (hasCycle){
    ss << "]+";
  }
  ss << "\n";
  return ss.str();
}

void Searcher::scanForSinglePath(Node* u, Path& path, Action &action) {
  bool baseCase = false;

  if(u->isOnPath()){
    // Reached a cycle
    baseCase = true;
  }
  else if(u->isLeafNode()){
    // Reached a leaf node
    baseCase = true;

    // Add u to the path
    path.push_back(std::make_pair(u, (Edge *)NULL));
    u->onPath = false;
  }

  if(baseCase){
    // Check if the path is a suitable one
    if(existsAction(path, action)){
      output_paths.push_back(path);
    }
  }
  else{
    // Mark u to be on the path
    u->onPath = true;
    for(Node::TransitionList::iterator it = u->beginTransitions(), et = u->endTransitions();
        it != et; ++it){
      // Add (u, edge) to the path
      std::pair< Node*, Edge* > path_elem = std::make_pair(u, it->first);
      path.push_back(path_elem);

      // Explore (v = adj(u, e)
      scanForSinglePath(it->second, path, action);

      // Remove (u, e) from the path
      Path::iterator path_it = std::find(path.begin(), path.end(), path_elem);
      if(path_it == path.end()){
        FATAL_ERROR("Path must contain <" << path_elem.first->name << ", " << path_elem.second->ID << ">"
            << " and Path is -- " << toString(path));
      }
      path.erase(path_it, path.end());

    }
    // Reset u to be not on the path
    u->onPath = false;
  }
}

bool Searcher::findPaths(Action action) {
  Node *root = graph->getRoot();
  FANCY_ASSERT("Root node can't be NULL", root != NULL);

  // Root node is always on path
  root->onPath = true;

  output_paths.clear();

  // For each edge of the root search for a single path
  for(Node::TransitionList::iterator it = root->beginTransitions(), et = root->endTransitions();
      it != et; ++it){
    // Create a new path
    Path path;

    // Add (root, the edge)
    path.push_back(std::make_pair(root, it->first));

    // scan for a single path from it->second
    scanForSinglePath(it->second, path, action);

  }

  if (output_paths.empty())
    return false;
  else
    return true;
}

void Searcher::printPaths(ostream &os){
  if(output_paths.empty()){
    os << "Found no path for output" << endl;
  }
  else{
    for(std::vector<Path>::iterator it = output_paths.begin(), et = output_paths.end(); it != et;
        ++it){
      os << toString(*it);
    }
  }
}

string Searcher::toStringPathConditions(Path &p){
  stringstream ss;
  Node *cycle_start = NULL;
  bool hasCycle = false;

  // Find if the path has a cycle
  Path::reverse_iterator last_elem = p.rbegin();
  if(last_elem->second){
    cycle_start = last_elem->first->getEndNode(last_elem->second);
    if(cycle_start){
      hasCycle = true;
    }
  }

  int stepCount = 0;

  for(Path::iterator it = p.begin(), et = p.end(); it != et; ){
    if(hasCycle){
      if(it->first == cycle_start){
        ss << "---CYCLE_STARTS_FROM_HERE---\n";
      }
    }
    ss << "step " << stepCount++ << ": " << it->second->toStringEdgeConditions();

    ++it;
    if(it != et){
      ss << "\n";
    }
  }
  ss << "\n";
  return ss.str();
}

void Searcher::printAbstractTestCases(std::string prefix){
  if(output_paths.empty()){
    cerr << "Found no path for output" << endl;
    return;
  }

  string filename;
  stringstream ss;
  int count = 0;
  for(std::vector<Path>::iterator it = output_paths.begin(), et = output_paths.end(); it != et;
      ++it){
    ss << prefix << "-" << count << ".txt";
    filename = ss.str();

    ofstream fout(filename.c_str(), ios_base::out);
    if(!fout.is_open())
      FATAL_ERROR("Failed to open file: " << filename);

    fout << toStringPathConditions(*it).c_str();

    fout.close();
    ss.str(string()); // clear stream
    count++;
  }

}

void Searcher::printPaths() {
  printPaths(std::cout);
}
