#ifndef PASSWORD_FILE_IO_CRYPTOFAILUREEXCEPTION_H
#define PASSWORD_FILE_IO_CRYPTOFAILUREEXCEPTION_H

#include "../global.h"

#include <stdexcept>
#include <string>

namespace Io {

class PASSWORD_FILE_EXPORT CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string &message) noexcept;
    explicit CryptoException(const char *message) noexcept;
    ~CryptoException() override;
};

} // namespace Io

#endif // PASSWORD_FILE_IO_CRYPTOFAILUREEXCEPTION_H
