//== config.h -----------------------------------------==//
//
//  Created on: Apr 27, 2016
//      Author: Endadul Hoque (mhoque@purdue.edu)
//==-------------------------------------------------------==//

#ifndef INCLUDE_CONFIG_H_
#define INCLUDE_CONFIG_H_

#include <iostream>
#include <cstdlib>
#include <cassert>
#include <sstream>

/// Print functions
#ifdef ENABLE_DEBUG
#define PRINT_LOG(msg)   do{ \
    std::cerr << "Debug: " << msg << "\n"; \
} while(0)
#else
#define PRINT_LOG(msg) (void)0
#endif

#define FATAL_ERROR(msg)   do{ \
    std::cerr << "Error: " << msg << "\n"; \
    exit(1); \
} while(0)


#define FANCY_ASSERT(msg, cond) do{ \
  if(!(cond)){\
    std::stringstream ss; \
    ss << msg;  \
    assert((cond) && ss.str().c_str()); \
  }\
}  while(0)



#endif /* INCLUDE_CONFIG_H_ */
