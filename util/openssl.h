#ifndef PASSWORD_FILE_UTIL_OPENSSL_H
#define PASSWORD_FILE_UTIL_OPENSSL_H

#include "../global.h"

#include <cstddef>
#include <cstdint>

namespace Util {

namespace OpenSsl {

struct Sha256Sum {
    static constexpr std::size_t size = 32;
    unsigned char data[size] = { 0 };
};

PASSWORD_FILE_EXPORT void init();
PASSWORD_FILE_EXPORT void clean();
PASSWORD_FILE_EXPORT Sha256Sum computeSha256Sum(const unsigned char *buffer, std::size_t size);
PASSWORD_FILE_EXPORT std::uint32_t generateRandomNumber(std::uint32_t min, std::uint32_t max);

} // namespace OpenSsl
} // namespace Util

#endif // PASSWORD_FILE_UTIL_OPENSSL_H
