//== string-operations.h -----------------------------------------==//
//
// This string util functions are part of CHIRON project
//  Created on: Jul 10, 2015
//      Author: Endadul Hoque (mhoque@purdue.edu)
//==-------------------------------------------------------==//

#ifndef INCLUDE_STRING_OPERATIONS_H_
#define INCLUDE_STRING_OPERATIONS_H_


#include <string>
#include <algorithm>
#include <cctype>

namespace strop{

const std::string WHITE_SPACES = " \t\n\r\f\v";

// trim from left
inline std::string& ltrim(std::string& s, const std::string whitespaces = " \t\n\r\f\v")
{
  std::size_t found = s.find_first_not_of(whitespaces);
  if (found != std::string::npos)
    s.erase(0, found);
  else
    s.clear(); // to handle string with all whitespaces
  return s;
}

// trim from right
inline std::string& rtrim(std::string& s, const std::string whitespaces = " \t\n\r\f\v")
{
  std::size_t found = s.find_last_not_of(whitespaces);
  if (found != std::string::npos)
    s.erase(found+1);
  else
    s.clear();
  return s;
}

// trim from left & right
inline std::string& trim(std::string& s, const std::string whitespaces = " \t\n\r\f\v")
{
    return ltrim(rtrim(s, whitespaces), whitespaces);
}

/*
 * Replace multiple spaces with one in STL string
 */
inline bool BothAreSpaces(char lhs, char rhs) { return (lhs == rhs) && (lhs == ' '); }
inline void replaceExtraSpacesWithOne(std::string &str){
  std::string::iterator new_end = std::unique(str.begin(), str.end(), BothAreSpaces);
  str.erase(new_end, str.end());
}

/*
 * Remove whitespaces from string
 */
inline void removeWhitespaces(std::string &str){
  str.erase(std::remove_if(str.begin(), str.end(), isspace), str.end());
}

/*
 * Convert string to lowercase
 */
inline void stringToLower(std::string &str){
  std::transform(str.begin(), str.end(), str.begin(),(int (*)(int))tolower);
}

/*
 * Convert string to uppercase
 */
inline void stringToUpper(std::string &str){
  std::transform(str.begin(), str.end(), str.begin(),(int (*)(int))toupper);
}


// Split a given string based on a delimiter and returns a vector of
// resulted strings
inline std::vector<std::string>
splitString(const std::string &str, const std::string &delimiter){
  std::vector<std::string> token_list;
  std::string s(str);
  size_t pos = 0;
  std::string token;
  while ((pos = s.find(delimiter)) != std::string::npos) {
      token = s.substr(0, pos);
      if(!token.empty())
        token_list.push_back(token);
      s.erase(0, pos + delimiter.length());
  }
  if(!s.empty())
    token_list.push_back(s);
  return token_list;
}

// @brief - Remove prefix, if present, from a given string
// @param  argstring  The string that may contain the given prefix
// @param  prefix  The prefix string
//
// @return  the modified string
inline std::string
removePrefix(const std::string &argstring, const std::string &prefix){
  if (!argstring.compare(0, prefix.length(), prefix)){
    return argstring.substr(prefix.length());
  }
  else
    return argstring.substr(0);
}

} // namespace strop

#endif /* INCLUDE_CRONUS_UTILS_STRING_OPERATIONS_H_ */
