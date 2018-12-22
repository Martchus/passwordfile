#include "./parsingexception.h"

namespace Io {

/*!
 * \class ParsingException
 * \brief The exception that is thrown when a parsing error occurs.
 * \remarks Must not have any inline methods/c'tors/d'tors (so the vtable is invoked in any compile unit).
 *          Otherwise it is not possible to throw/catch it accross library boundaries under Android.
 */

/*!
 * \brief Constructs a parsing exception.
 */
ParsingException::ParsingException(const std::string &message) noexcept
    : runtime_error(message)
{
}

/*!
 * \brief Constructs a parsing exception.
 */
ParsingException::ParsingException(const char *message) noexcept
    : runtime_error(message)
{
}

/*!
 * \brief Destroys the parsing exception.
 */
ParsingException::~ParsingException()
{
}

} // namespace Io
