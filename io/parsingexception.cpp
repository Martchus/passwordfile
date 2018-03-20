#include "./parsingexception.h"

namespace Io {

/*!
 * \class ParsingException
 * \brief The exception that is thrown when a parsing error occurs.
 */

/*!
 * \brief Constructs a parsing exception.
 */
ParsingException::ParsingException(const std::string &message) noexcept
    : runtime_error(message)
{
}

/*!
 * \brief Destroys the exception.
 */
ParsingException::~ParsingException() noexcept
{
}
}
