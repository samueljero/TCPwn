//== graph.cpp -----------------------------------------==//
//
//  Created on: Apr 27, 2016
//      Author: Endadul Hoque (mhoque@purdue.edu)
//==-------------------------------------------------------==//


#include <sstream>
#include <fstream>

#include "graph.h"
#include "config.h"
#define ENABLE_DEBUG


#define RAPIDXML_NO_EXCEPTIONS /// Disable std::exception
#include "rapidxml-1.13/rapidxml.hpp" /// Processing xml

using namespace std;

// For processing XML input file
#define XSD_DEF(name, value)   static const char* XSD_ ## name = value
// XML nodes
XSD_DEF(Graph         ,    "FSM"            );
XSD_DEF(Nodes         ,    "States"         );
XSD_DEF(Node          ,    "State"          );
XSD_DEF(NodeName      ,    "name"           );
XSD_DEF(Edges         ,    "Transitions"    );
XSD_DEF(Edge          ,    "Transition"     );
XSD_DEF(EdgeCurState  ,    "CurrentState"   );
XSD_DEF(EdgeConditions,    "Conditions"     );
XSD_DEF(EdgeCondition ,    "Condition"      );
XSD_DEF(EdgeActions   ,    "Actions"        );
XSD_DEF(EdgeAction    ,    "Action"         );
XSD_DEF(EdgeNextState ,    "NextState"      );
XSD_DEF(GraphRootNode ,    "InitialState"   );



string Node::toString(){
  stringstream ss;
  ss << "{Node: " << ID  << ", name: " << name << "}";
  return ss.str();
}

string Edge::toString(){
  stringstream ss;
  ss << "{Edge: " << ID;
  if(!conditions.empty()){
    ss << ", [Cond: ";
  }
  for(vector<Condition>::iterator it = conditions.begin(), et = conditions.end();
      it != et; ){
    ss << *it;
    ++it;
    if (it != et)
      ss << " && ";
    else
      ss << "]";
  }
  if(!actions.empty()){
    ss << ", [Action: ";
  }
  for(vector<Condition>::iterator it = actions.begin(), et = actions.end();
      it != et; ){
    ss << *it;
    ++it;
    if (it != et)
      ss << " && ";
    else
      ss << "]";
  }
  ss << "}";

  return ss.str();
}

string Edge::toStringEdgeConditions(){
  stringstream ss;
  for(vector<Condition>::iterator it = conditions.begin(), et = conditions.end();
      it != et; ){
    ss << *it;
    ++it;
    if (it != et)
      ss << " && ";
  }
  return ss.str();
}

string Graph::toString(){
  stringstream ss;
  ss << "*** Begin Graph ***\n";
  for(std::map<unsigned int, struct Node* >::iterator it = graphNodes.begin(),
      et = graphNodes.end(); it != et; ++it){
    ss << it->second->toString() << "\n";
  }
  unsigned int count = 0;
  for(std::map<unsigned int, struct Node* >::iterator it = graphNodes.begin(),
      et = graphNodes.end(); it != et; ++it){
    for(vector<Node::Transition>::iterator tran_it = it->second->transitions.begin(),
        tran_et = it->second->transitions.end(); tran_it != tran_et; ++tran_it){
      ss << "======= Transition #" << count << " ========\n";
      ss << "Start node: " << it->second->ID << "\n";
      ss << "Edge label: " << tran_it->first->toString() << "\n";
      ss << "End node: " << tran_it->second->ID << "\n";
      ++count;
    }
  }
  ss << "Root node: " << root->toString() << "\n";
  ss << "Total nodes: " << nodeCount << "\n";
  ss << "Total edges: " << edgeCount << "\n";
  ss << "*** End Graph ***\n";
  return ss.str();
}


void Graph::insertNode(string &name)
{
  if(existsNodeName(name)){
    FATAL_ERROR("Duplicate attribute (" << name << ") for " << XSD_Node);
  }
  Node *node = new Node(nodeCount, name);
  graphNodes[nodeCount] = node;
  nodeNameToID[name] = nodeCount;
  nodeCount++;
}

Node* Graph::getNode(string &name){
  if(!existsNodeName(name)){
    FATAL_ERROR("No " << XSD_Node << " with attribute (" << XSD_NodeName << " = " << name << ")");
  }
  return graphNodes[nodeNameToID[name]];
}

void Graph::insertEdge(std::string &start_node, std::string &finish_node,
        std::vector<Condition> &conditions, std::vector<Action> &actions)
{
  if(!existsNodeName(start_node)){
    FATAL_ERROR("No " << XSD_Node << " with attribute (" << XSD_NodeName << " = " << start_node << ")");
  }
  else if(!existsNodeName(finish_node)){
    FATAL_ERROR("No " << XSD_Node << " with attribute (" << XSD_NodeName << " = " << finish_node << ")");
  }

  Edge *edge = new Edge(edgeCount);
  for(std::vector<Condition>::iterator it = conditions.begin(), et = conditions.end(); it != et;
      ++it){
    edge->addCondition(*it);
  }
  for(std::vector<Action>::iterator it = actions.begin(), et = actions.end(); it != et;
      ++it){
    edge->addAction(*it);
  }

  Node *begin_node = getNode(start_node);
  Node *end_node = getNode(finish_node);
  begin_node->addTransition(edge, end_node);

  edgeCount++;
}

Graph::Graph(string filename):nodeCount(0), edgeCount(0){
  using namespace rapidxml;

  xml_document<> doc;
  xml_node<> *root_node;

  // Read the xml file into a vector
  ifstream theFile (filename.c_str());
  if(!theFile){
    FATAL_ERROR("No such file: " << filename);
  }
  PRINT_LOG("Parsing " << filename << " file...");
  vector<char> buffer((istreambuf_iterator<char>(theFile)), istreambuf_iterator<char>());
  buffer.push_back('\0');
  theFile.close();

  // Parse the buffer using the xml file parsing library into doc
  doc.parse<0>(&buffer[0]);

  // Find our root node
  root_node = doc.first_node(XSD_Graph);

  // Get the node list
  xml_node<> *node_list = root_node->first_node(XSD_Nodes);
  FANCY_ASSERT("No " << XSD_Nodes << " in " << filename, node_list);

  // Iterate over the node list
  for(xml_node<> *graph_node = node_list->first_node(XSD_Node);
        graph_node; graph_node = graph_node->next_sibling()){

    // Extract name
    string node_name = graph_node->first_attribute(XSD_NodeName)->value();
    FANCY_ASSERT("Invalid value for attribute (" << XSD_NodeName << ") of " << XSD_Node << " in " << filename,
        !node_name.empty());
    // add node
    insertNode(node_name);
  }

  // Iterate over the edges
  xml_node<> *edge_list = root_node->first_node(XSD_Edges);
  FANCY_ASSERT("No " << XSD_Edges << " in " << filename, edge_list);
  for(xml_node<> *edge = edge_list->first_node(XSD_Edge);
        edge; edge = edge->next_sibling()){

    // Extract edge info
    string start_node = edge->first_node(XSD_EdgeCurState)->value();
    string end_node = edge->first_node(XSD_EdgeNextState)->value();

    // Extract conditions
    xml_node<> *cond_list = edge->first_node(XSD_EdgeConditions);
    FANCY_ASSERT("No " << XSD_EdgeConditions << " in " << filename, cond_list);
    vector<Condition> conditions;
    for(xml_node<> *cond = cond_list->first_node(XSD_EdgeCondition); cond;
        cond = cond->next_sibling()){
      FANCY_ASSERT(XSD_EdgeCondition << " can't be NULL", cond->value());
      conditions.push_back(cond->value());
    }

    // Extract actions
    xml_node<> *action_list = edge->first_node(XSD_EdgeActions);
    FANCY_ASSERT("No " << XSD_EdgeActions << " in " << filename, action_list);
    vector<Condition> actions;
    for(xml_node<> *ac = action_list->first_node(XSD_EdgeAction); ac;
        ac = ac->next_sibling()){
      FANCY_ASSERT(XSD_EdgeAction << " can't be NULL", ac->value());
      actions.push_back(ac->value());
    }

    // add the edge
    insertEdge(start_node, end_node, conditions, actions);
  }

  // Extract root node of the graph
  xml_node<> *graph_root_node = root_node->first_node(XSD_GraphRootNode);
  FANCY_ASSERT("No " << XSD_GraphRootNode << " in " << filename, graph_root_node);
  string root_node_name = graph_root_node->value();
  this->root = getNode(root_node_name);

  PRINT_LOG("Loaded graph from " << filename << " file...");
}


Graph::~Graph(){
  for(std::map<unsigned int, struct Node* >::iterator it = graphNodes.begin(), et = graphNodes.end();
      it != et; ++it){
    Node *node = it->second;
    for(std::vector<Node::Transition>::iterator nit = node->transitions.begin(), net = node->transitions.end();
        nit != net; ++nit){
      delete nit->first; // Edge
    }
    delete node;
  }
}




void rapidxml::parse_error_handler(const char *what, void *where){
  FATAL_ERROR("XML Parser error: \"" << what << "\" at " << where);
}



