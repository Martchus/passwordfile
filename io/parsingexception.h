#ifndef PARSINGEXCEPTION_H
#define PARSINGEXCEPTION_H

#include <c++utilities/application/global.h>

#include <stdexcept>
#include <string>

namespace Io {

class LIB_EXPORT ParsingException : public std::runtime_error
{
public:
    ParsingException(const std::string &message = std::string()) USE_NOTHROW;
    virtual ~ParsingException() USE_NOTHROW;
};

}

#endif // PARSINGEXCEPTION_H
