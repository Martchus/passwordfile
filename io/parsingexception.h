#ifndef PARSINGEXCEPTION_H
#define PARSINGEXCEPTION_H

#include "../global.h"

#include <stdexcept>
#include <string>

namespace Io {

class PASSWORD_FILE_EXPORT ParsingException : public std::runtime_error
{
public:
    ParsingException(const std::string &message = std::string()) USE_NOTHROW;
    virtual ~ParsingException() USE_NOTHROW;
};

}

#endif // PARSINGEXCEPTION_H
