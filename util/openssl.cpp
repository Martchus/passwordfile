#include "openssl.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace Util {

namespace OpenSsl {

void init()
{
    // load the human readable error strings for libcrypto
    ERR_load_crypto_strings();
    // load all digest and cipher algorithms
    OpenSSL_add_all_algorithms();
    // load config file, and other important initialisation
    OPENSSL_config(NULL);
}

void clean()
{
    // removes all digests and ciphers
    EVP_cleanup();
    // remove error strings
    ERR_free_strings();
}

}

}
