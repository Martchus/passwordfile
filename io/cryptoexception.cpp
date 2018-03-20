#include "./cryptoexception.h"

namespace Io {
/*!
 * \class CryptoException
 * \brief The exception that is thrown when an encryption/decryption error occurs.
 */

/*!
 * \brief Constructs a crypto exception.
 */
CryptoException::CryptoException(const std::string &openSslErrorQueue) noexcept
    : runtime_error(openSslErrorQueue)
{
}

/*!
 * \brief Destroys the exception.
 */
CryptoException::~CryptoException() noexcept
{
}
} // namespace Io
