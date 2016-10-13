//== Graph.h -----------------------------------------==//
//
//  Created on: Apr 27, 2016
//      Author: Endadul Hoque (mhoque@purdue.edu)
//==-------------------------------------------------------==//

#ifndef INCLUDE_GRAPH_H_
#define INCLUDE_GRAPH_H_

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <strings.h>
#include "string-operations.h"

inline bool isEqualIgnoreCase(const std::string &str1, const std::string &str2){
  std::string lhs = str1;
  std::string rhs = str2;
  strop::removeWhitespaces(lhs);
  strop::removeWhitespaces(rhs);
  strop::stringToLower(lhs);
  strop::stringToLower(rhs);

  if(lhs.find(rhs /* since rhs is action */) != std::string::npos){
    return true; // found
  }
  else
    return false; // not found

//  return strcasecmp(lhs.c_str(), rhs.c_str()) == 0;
}

// Graph classes and structs
struct Edge; // Forward declaration
typedef std::string Action;
typedef std::string Condition;


struct Node{
  public:
    unsigned int ID;
    std::string name;

    typedef std::pair<struct Edge*, struct Node*> Transition;

    std::vector< Transition > transitions;


    /// Gross!! Special members used by searcher
    bool onPath;

    Node(unsigned int _id, std::string _name): ID(_id),
        name(_name), onPath(false){}
    ~Node(){}

    std::string toString();

    bool isOnPath() {return onPath;}

    bool isLeafNode() { return transitions.empty();}

    void addTransition(struct Edge *edge, struct Node* next){
      transitions.push_back(std::make_pair(edge, next));
    }

    typedef std::vector< Transition > TransitionList;
    TransitionList::iterator beginTransitions(){return transitions.begin();}
    TransitionList::iterator endTransitions(){return transitions.end();}

    Node* getEndNode(struct Edge *edge){
      for(TransitionList::iterator it = transitions.begin(), et = transitions.end();
          it != et; ++it){
        if(it->first == edge){
          return it->second;
        }
      }
      return NULL;
    }
};

typedef struct Node Node;

struct Edge{
  public:
    unsigned int ID;
    std::vector<Condition> conditions;
    std::vector<Action> actions;
    Edge(unsigned int _id) : ID(_id){}
    ~Edge(){}
    void addCondition(Condition c){conditions.push_back(c);}
    void addAction(Action a){actions.push_back(a);}

    bool containsAction(const Action &action){
      for(std::vector<Action>::iterator it = actions.begin(), et = actions.end();
          it != et; ++it){
        if (isEqualIgnoreCase(*it, action)){
          return true;
        }
      }
      return false;
    }

    std::string toString();
    std::string toStringEdgeConditions();
};
typedef struct Edge Edge;


class Graph{
  private:
    std::map<unsigned int, struct Node* > graphNodes;
    std::map<std::string, unsigned int> nodeNameToID;


    unsigned int nodeCount;
    unsigned int edgeCount;
    Node *root;

    Graph (const Graph&);
    void operator=(const Graph&);

    // Exists
    bool existsNodeName(std::string &name){
      return nodeNameToID.find(name) != nodeNameToID.end();
    }

//    bool existsNodeName(const std::string &name){
//      return nodeNameToID.find(name) != nodeNameToID.end();
//    }

    struct Node* getNode(std::string &name);

    // Insert node
    void insertNode(std::string &name);
    // Insert edge
    void insertEdge(std::string &start_node, std::string &end_node,
        std::vector<Condition> &conditions, std::vector<Action> &actions);

  public:
    explicit Graph(std::string graph_file_name);
    ~Graph();

    // print functions
    void printGraph(){
      std::cout << toString();
    }
    std::string toString();


    // Root
    Node* getRoot(){return root;}

    typedef std::map<unsigned int, struct Node* > GraphNodes_t;

    GraphNodes_t::iterator beginGraphNodes(){return graphNodes.begin();}
    GraphNodes_t::iterator endGraphNodes(){return graphNodes.end();}
};


#endif /* INCLUDE_GRAPH_H_ */
