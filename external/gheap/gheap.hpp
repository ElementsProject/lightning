// Pass -DGHEAP_CPP11 to compiler for including gheap optimized for C++11.
// Otherwise gheap optimized for C++03 will be included.

#ifdef GHEAP_CPP11
#  include "gheap_cpp11.hpp"
#else
#  include "gheap_cpp03.hpp"
#endif
