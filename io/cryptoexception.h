#ifndef CRYPTOFAILUREEXCEPTION_H
#define CRYPTOFAILUREEXCEPTION_H

#include "../global.h"

#include <stdexcept>
#include <string>

namespace Io {

class PASSWORD_FILE_EXPORT CryptoException : public std::runtime_error {
public:
    CryptoException(const std::string &openSslErrorQueue) noexcept;
    ~CryptoException() noexcept;
};
}

#endif // CRYPTOFAILUREEXCEPTION_H
