#include "./openssl.h"

#include "../io/cryptoexception.h"

#include <c++utilities/chrono/datetime.h>
#include <c++utilities/conversion/binaryconversion.h>
#include <c++utilities/conversion/stringbuilder.h>
#include <c++utilities/conversion/stringconversion.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef OPENSSL_VERSION_MAJOR
#if OPENSSL_VERSION_MAJOR >= 3
#define PASSWORD_FILE_USE_OPENSSL_PROVIDER_API
#include <openssl/provider.h>
#endif
#endif

#include <array>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

/*!
 * \brief Contains utility classes and functions.
 */
namespace Util {

/*!
 * \brief Contains functions utilizing the usage of OpenSSL.
 */
namespace OpenSsl {

static_assert(Sha256Sum::size == SHA256_DIGEST_LENGTH, "SHA-256 sum fits into Sha256Sum struct");

namespace {
/*!
 * \brief Decodes a Base32 encoded string.
 * \throws Throws CppUtilities::ConversionException if \a input is no valid Base32 encoded string.
 */
static std::vector<std::uint8_t> decodeBase32(std::string_view input)
{
    auto result = std::vector<std::uint8_t>();
    result.reserve((input.size() * 5 + 7) / 8);
    auto buffer = std::uint32_t();
    auto bitsLeft = 0;
    for (char c : input) {
        int value;
        if (c >= 'A' && c <= 'Z') {
            value = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            value = c - 'a';
        } else if (c >= '2' && c <= '7') {
            value = c - '2' + 26;
        } else if (c == '=') {
            break;
        } else if (std::isspace(static_cast<unsigned char>(c))) {
            continue;
        } else {
            throw CppUtilities::ConversionException("Base32 encoded secret contains invalid character");
        }
        buffer = (buffer << 5) | static_cast<std::uint32_t>(value);
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            result.push_back(static_cast<std::uint8_t>((buffer >> (bitsLeft - 8)) & 0xFF));
            bitsLeft -= 8;
        }
    }
    return result;
}

/*!
 * \brief Extracts a query parameter from the URL.
 * \remarks This is a simple implementation and does not handle URL decoding.
 * \throws Throws a CppUtilities::ConversionException() if \a url does not contain \a param and \a fallback is empty.
 */
static std::string_view getQueryParam(std::string_view url, std::string_view param, std::string_view fallback = std::string_view())
{
    const auto queryStart = url.find('?');
    if (queryStart == std::string_view::npos) {
        if (fallback.empty()) {
            throw CppUtilities::ConversionException("query parameters missing");
        }
        return fallback;
    }
    const auto query = url.substr(queryStart + 1);
    auto pos = std::size_t();
    while (pos != std::string_view::npos) {
        const auto nextPos = query.find('&', pos);
        const auto pair = query.substr(pos, nextPos == std::string_view::npos ? nextPos : nextPos - pos);
        const auto eqPos = pair.find('=');
        if (eqPos != std::string_view::npos && pair.substr(0, eqPos) == param) {
            return pair.substr(eqPos + 1);
        }
        pos = nextPos == std::string_view::npos ? nextPos : nextPos + 1;
    }
    if (fallback.empty()) {
        throw CppUtilities::ConversionException(CppUtilities::argsToString(param, " is empty/missing"));
    }
    return fallback;
}
} // namespace

#ifdef PASSWORD_FILE_USE_OPENSSL_PROVIDER_API
static OSSL_PROVIDER *provider = nullptr;
#endif

/*!
 * \brief Initializes OpenSSL.
 */
void init()
{
    // load the human readable error strings for libcrypto (for compatibility with OpenSSL < 1.1.0)
    ERR_load_crypto_strings();

    // load all digest and cipher algorithms (for compatibility with OpenSSL < 1.1.0)
    OpenSSL_add_all_algorithms();

    // ensure the default provider is loaded
    // note: Other libraries like the Qt Network plugin might configure their own provider contexts
    //       explicitly. This explicit configuration disables the automatic fallback for loading the
    //       "default" provider globally - which we therefore need to do explicitly as well.
#ifdef PASSWORD_FILE_USE_OPENSSL_PROVIDER_API
    if (!(provider = OSSL_PROVIDER_load(nullptr, "default"))) {
        std::cerr << "Unable to load default OpenSSL provider.\n";
    }
#endif
}

/*!
 * \brief Cleans resources of OpenSSL.
 */
void clean()
{
    // removes all digests and ciphers (for compatibility with OpenSSL < 1.1.0)
    EVP_cleanup();

    // remove error strings (for compatibility with OpenSSL < 1.1.0)
    ERR_free_strings();

    // unload default provider
#ifdef PASSWORD_FILE_USE_OPENSSL_PROVIDER_API
    if (provider) {
        OSSL_PROVIDER_unload(provider);
    }
#endif
}

/*!
 * \brief Computes a SHA-256 sum using OpenSSL.
 */
Sha256Sum computeSha256Sum(const unsigned char *buffer, std::size_t size)
{
    auto hash = Sha256Sum();
    SHA256(buffer, size, hash.data);
    return hash;
}

/*!
 * \brief Computes an HMAC-SHA256 using OpenSSL.
 */
Sha256Sum computeHmacSha256(const unsigned char *key, std::size_t keySize, const unsigned char *data, std::size_t dataSize)
{
    auto result = Sha256Sum();
    unsigned int resultLen = Sha256Sum::size;
    if (HMAC(EVP_sha256(), key, static_cast<int>(keySize), data, dataSize, result.data, &resultLen) == nullptr) {
        throw Io::CryptoException("HMAC-SHA256 computation failed.");
    }
    return result;
}

/*!
 * \brief Generates a random number using OpenSSL.
 */
std::uint32_t generateRandomNumber(std::uint32_t min, std::uint32_t max)
{
    auto val = std::uint32_t();
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&val), sizeof(val)) != 1) {
        auto errorMsg = std::string();
        while (unsigned long errorCode = ERR_get_error()) {
            if (!errorMsg.empty())
                errorMsg += '\n';
            errorMsg += ERR_error_string(errorCode, nullptr);
        }
        throw Io::CryptoException(std::move(errorMsg));
    }
    return min + (val % (max - min + 1));
}

/*!
 * \brief Compute a token following the TOTP standard (RFC 6238).
 * \param url Specifies a URL containing the secret and parameters, e.g. "otpauth://totp/some/path?secret=ABCDABCDABCDABCD&period=30&digits=6&issuer=some_issuer".
 * \param time Specifies the time to compute the for (UTC).
 * \return Returns the token with as many number of digits as specified in the URL.
 * \throws
 * - Throws a CppUtilities::ConversionException if URL parameters are invalid/missing.
 * - Throws an Io::CryptoException if an error occurs during cryptographic computation.
 */
TOTP computeTOTP(std::string_view url, CppUtilities::DateTime time)
{
    // read parameters from URL
    const auto secret = decodeBase32(getQueryParam(url, "secret"));
    const auto period = CppUtilities::stringToNumber<std::uint64_t>(getQueryParam(url, "period", "30"));
    const auto digits = CppUtilities::stringToNumber<int>(getQueryParam(url, "digits", "6"));
    const auto algo = getQueryParam(url, "algorithm", "SHA1");
    if (period < 1 || digits < 1) {
        throw CppUtilities::ConversionException("period and digits must be >= 1");
    }
    if (digits > 10) {
        throw CppUtilities::ConversionException("digits must be <= 10");
    }

    // encode the counter as a 64-bit big-endian integer as per RFC 6238
    auto timeStamp = static_cast<std::uint64_t>(time.toTimeStamp());
    auto counter = timeStamp / period;
    auto remaining = period - (timeStamp % period);
    auto counterBytes = std::array<unsigned char, 8>();
    CppUtilities::BE::getBytes(counter, reinterpret_cast<char *>(counterBytes.data()));

    // create context
    EVP_MAC *const mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) {
        throw Io::CryptoException("EVP_MAC_fetch failed for algorithm=HMAC");
    }
    EVP_MAC_CTX *const ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        throw Io::CryptoException("EVP_MAC_CTX_new failed");
    }

    // init params for specified algorithm
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(algo.data()), 0);
    params[1] = OSSL_PARAM_construct_end();

    // supply secret
    if (EVP_MAC_init(ctx, secret.data(), secret.size(), params) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw Io::CryptoException("EVP_MAC_init failed");
    }

    // supply counter
    if (EVP_MAC_update(ctx, counterBytes.data(), counterBytes.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw Io::CryptoException("EVP_MAC_update failed");
    }

    // get result
    auto out = std::array<unsigned char, EVP_MAX_MD_SIZE>();
    auto outLen = std::size_t();
    if (EVP_MAC_final(ctx, out.data(), &outLen, out.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw Io::CryptoException("EVP_MAC_final failed");
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    // return token digits as string
    const auto offset = static_cast<std::size_t>(out[outLen - 1] & 0x0F);
    const auto truncatedHash = (static_cast<std::uint32_t>(out[offset] & 0x7F) << 24) | (static_cast<std::uint32_t>(out[offset + 1] & 0xFF) << 16)
        | (static_cast<std::uint32_t>(out[offset + 2] & 0xFF) << 8) | static_cast<std::uint32_t>(out[offset + 3] & 0xFF);
    const auto otp = truncatedHash % static_cast<std::uint32_t>(std::pow(10, digits));
    return TOTP{
        .digits = (std::ostringstream() << std::setfill('0') << std::setw(digits) << otp).str(),
        .period = CppUtilities::TimeSpan::fromSeconds(static_cast<double>(period)),
        .remaining = CppUtilities::TimeSpan::fromSeconds(static_cast<double>(remaining)),
    };
}

} // namespace OpenSsl
} // namespace Util
