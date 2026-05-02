#include "./openssl.h"
#include "./opensslrandomdevice.h"

#include "../io/cryptoexception.h"

#include <c++utilities/chrono/datetime.h>
#include <c++utilities/conversion/binaryconversion.h>
#include <c++utilities/conversion/stringconversion.h>
#include <c++utilities/conversion/stringbuilder.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#include <array>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
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
    auto hash = Sha256Sum();
    SHA256(buffer, size, hash.data);
    return hash;
}

/*!
 * \brief Generates a random number using OpenSSL.
 */
std::uint32_t generateRandomNumber(std::uint32_t min, std::uint32_t max)
{
    OpenSslRandomDevice dev;
    std::default_random_engine rng(dev());
    std::uniform_int_distribution<std::uint32_t> dist(min, max);
    return dist(rng);
}

/*!
 * \brief Compute a token following the TOTP standard (RFC 6238).
 * \param url Specifies a URL containing the secret and parameters, e.g. "otpauth://totp/some/path?secret=ABCDABCDABCDABCD&period=30&digits=6&issuer=some_issuer".
 * \param time Specifies the time to compute the for (UTC).
 * \return Returns the token with as many number of digits as specified in the URL.
 * \throws
 * - Throws a CppUtilities::ConversionException if URL parameters are invalid/missing.
 * - Throws a Io::CryptoException if an error occurrs during cryptographic computation.
 */
std::string computeTOTP(std::string_view url, CppUtilities::DateTime time)
{
    // read parameters from URL
    const auto secret = decodeBase32(getQueryParam(url, "secret"));
    const auto period = CppUtilities::stringToNumber<int>(getQueryParam(url, "period", "30"));
    const auto digits = CppUtilities::stringToNumber<int>(getQueryParam(url, "digits", "6"));
    const auto algo = getQueryParam(url, "algorithm", "SHA1");

    // encode the counter as a 64-bit big-endian integer as per RFC 6238
    auto counterBytes = std::array<unsigned char, 8>();
    CppUtilities::BE::getBytes(static_cast<std::uint64_t>(time.toTimeStamp()) / static_cast<std::uint64_t>(period), reinterpret_cast<char *>(counterBytes.data()));

    // create context
    EVP_MAC *const mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) {
        throw Io::CryptoException("EVP_MAC_fetch faild for algorithm=HMAC");
    }
    EVP_MAC_CTX *const ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        throw Io::CryptoException("EVP_MAC_CTX_new faild");
    }

    // init params for specified algorithm
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(algo.data()), 0);
    params[1] = OSSL_PARAM_construct_end();

    // supply secret
    if (EVP_MAC_init(ctx, secret.data(), secret.size(), params) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw Io::CryptoException("EVP_MAC_init faild");
    }

    // supply counter
    if (EVP_MAC_update(ctx, counterBytes.data(), counterBytes.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw Io::CryptoException("EVP_MAC_update faild");
    }

    // get result
    auto out = std::array<unsigned char, EVP_MAX_MD_SIZE>();
    auto outLen = std::size_t();
    if (EVP_MAC_final(ctx, out.data(), &outLen, out.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw Io::CryptoException("EVP_MAC_final faild");
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    // return token digits as string
    const auto offset = static_cast<std::size_t>(out[outLen - 1] & 0x0F);
    const auto truncatedHash = (static_cast<std::uint32_t>(out[offset] & 0x7F) << 24) | (static_cast<std::uint32_t>(out[offset + 1] & 0xFF) << 16)
        | (static_cast<std::uint32_t>(out[offset + 2] & 0xFF) << 8) | static_cast<std::uint32_t>(out[offset + 3] & 0xFF);

    const auto otp = truncatedHash % static_cast<std::uint32_t>(std::pow(10, digits));
    return (std::ostringstream() << std::setfill('0') << std::setw(digits) << otp).str();
}

} // namespace OpenSsl
} // namespace Util
