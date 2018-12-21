#ifndef PASSWORD_FILE_IO_PARSINGEXCEPTION_H
#define PASSWORD_FILE_IO_PARSINGEXCEPTION_H

#include "../global.h"

#include <stdexcept>
#include <string>

namespace Io {

class PASSWORD_FILE_EXPORT ParsingException : public std::runtime_error {
public:
    explicit ParsingException(const std::string &message = std::string()) noexcept;
    explicit ParsingException(const char *message) noexcept;
};

/*!
 * \brief Constructs a parsing exception.
 */
inline ParsingException::ParsingException(const std::string &message) noexcept
    : runtime_error(message)
{
}

/*!
 * \brief Constructs a parsing exception.
 */
inline ParsingException::ParsingException(const char *message) noexcept
    : runtime_error(message)
{
}

} // namespace Io

#endif // PASSWORD_FILE_IO_PARSINGEXCEPTION_H
