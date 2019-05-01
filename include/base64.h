#ifndef BASE64_H
#define BASE64_H
#include <string>

namespace base64
{
    std::string base64_encode(unsigned char const* , unsigned int len);
    std::string base64_decode(std::string const& s);
}

#endif