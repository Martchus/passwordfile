#include "./opensslrandomdevice.h"

#include "../io/cryptoexception.h"

#include <c++utilities/conversion/binaryconversion.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <string>

using namespace std;

namespace Util {

/*!
 * \class OpenSslRandomDevice
 * \brief Provides a random device using the OpenSSL function RAND_bytes().
 */

/*!
 * \brief Constructs a new random device.
 */
OpenSslRandomDevice::OpenSslRandomDevice()
{
}

/*!
 * \brief Generates a new random number.
 */
uint32 OpenSslRandomDevice::operator()() const
{
    unsigned char buf[4];
    if (RAND_bytes(buf, sizeof(buf))) {
        return ConversionUtilities::LE::toUInt32(reinterpret_cast<char *>(buf));
    }

    // handle error case
    string errorMsg;
    while (unsigned long errorCode = ERR_get_error()) {
        if (!errorMsg.empty()) {
            errorMsg += '\n';
        }
        errorMsg += ERR_error_string(errorCode, nullptr);
        errorCode = ERR_get_error();
    }
    throw Io::CryptoException(errorMsg);
}

/*!
 * \brief Returns the status.
 */
bool OpenSslRandomDevice::status() const
{
    return RAND_status();
}
} // namespace Util
