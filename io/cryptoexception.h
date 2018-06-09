#ifndef PASSWORD_FILE_IO_CRYPTOFAILUREEXCEPTION_H
#define PASSWORD_FILE_IO_CRYPTOFAILUREEXCEPTION_H

#include "../global.h"

#include <stdexcept>
#include <string>

namespace Io {

class PASSWORD_FILE_EXPORT CryptoException : public std::runtime_error {
public:
    CryptoException(const std::string &openSslErrorQueue) noexcept;
    ~CryptoException() noexcept;
};
} // namespace Io

#endif // PASSWORD_FILE_IO_CRYPTOFAILUREEXCEPTION_H
