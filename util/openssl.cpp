#include "./openssl.h"
#include "./opensslrandomdevice.h"

#include <c++utilities/conversion/binaryconversion.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <random>

/*!
 * \brief Contains utility classes and functions.
 */
namespace Util {

/*!
 * \brief Contains functions utilizing the usage of OpenSSL.
 */
namespace OpenSsl {

static_assert(Sha256Sum::size == SHA256_DIGEST_LENGTH, "SHA-256 sum fits into Sha256Sum struct");

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

/*!
 * \brief Computes a SHA-256 sum using OpenSSL.
 */
Sha256Sum computeSha256Sum(const unsigned char *buffer, std::size_t size)
{
    // init sha256 hashing
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    // do the actual hashing
    SHA256_Update(&sha256, buffer, size);

    // finalize the hashing
    Sha256Sum hash;
    SHA256_Final(hash.data, &sha256);
    return hash;
}

/*!
 * \brief Generates a random number using OpenSSL.
 */
uint32_t generateRandomNumber(uint32_t min, uint32_t max)
{
    OpenSslRandomDevice dev;
    std::default_random_engine rng(dev());
    std::uniform_int_distribution<uint32_t> dist(min, max);
    return dist(rng);
}

} // namespace OpenSsl
} // namespace Util
