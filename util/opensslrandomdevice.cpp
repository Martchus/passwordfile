#include "./opensslrandomdevice.h"

#include "../io/cryptoexception.h"

#include <c++utilities/conversion/binaryconversion.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#include <string>

using namespace std;

namespace Util {

/*!
 * \namespace QtGui
 * \brief Contains all miscellaneous utility functions.
 */

/*!
 * \class OpenSslRandomDevice
 * \brief Provides a random device using the OpenSSL function RAND_bytes().
 */

/*!
 * \brief Constructs a new random device.
 */
OpenSslRandomDevice::OpenSslRandomDevice()
{}

/*!
 * \brief Generates a new random number.
 */
uint32 OpenSslRandomDevice::operator ()() const {
    unsigned char buf[4];
    if(RAND_bytes(buf, sizeof(buf))) {
        return ConversionUtilities::LE::toUInt32(reinterpret_cast<char *>(buf));
    } else {
        string msg;
        unsigned long errorCode = ERR_get_error();
        while(errorCode != 0) {
            if(!msg.empty()) {
                msg += "\n";
            }
            msg += ERR_error_string(errorCode, 0);
            errorCode = ERR_get_error();
        }
        throw Io::CryptoException(msg);
    }
}

/*!
 * \brief Returns the status.
 */
bool OpenSslRandomDevice::status() const
{
    return RAND_status();
}

}
