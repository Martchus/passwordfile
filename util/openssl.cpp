#include "./openssl.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/*!
 * \brief Contains utility classes and functions.
 */
namespace Util {

/*!
 * \brief Contains functions utilizing the usage of OpenSSL.
 */
namespace OpenSsl {

/*!
 * \brief Initializes OpenSSL.
 */
void init()
{
    // load the human readable error strings for libcrypto
    ERR_load_crypto_strings();
    // load all digest and cipher algorithms
    OpenSSL_add_all_algorithms();
}

/*!
 * \brief Cleans resources of OpenSSL.
 */
void clean()
{
    // removes all digests and ciphers
    EVP_cleanup();
    // remove error strings
    ERR_free_strings();
}
} // namespace OpenSsl
} // namespace Util
