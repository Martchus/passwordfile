#include "./cryptoexception.h"

namespace Io {
/*!
 * \class CryptoException
 * \brief The exception that is thrown when an encryption/decryption error occurs.
 * \remarks Must not have any inline methods/c'tors/d'tors (so the vtable is invoked in any compile unit).
 *          Otherwise it is not possible to throw/catch it accross library boundaries under Android.
 */

/*!
 * \brief Constructs a crypto exception.
 */
CryptoException::CryptoException(const std::string &message) noexcept
    : runtime_error(message)
{
}

/*!
 * \brief Constructs a crypto exception.
 */
CryptoException::CryptoException(const char *message) noexcept
    : runtime_error(message)
{
}

/*!
 * \brief Destroys the crypto exception.
 */
CryptoException::~CryptoException()
{
}

} // namespace Io
