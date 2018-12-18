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

void PASSWORD_FILE_EXPORT init();
void PASSWORD_FILE_EXPORT clean();
Sha256Sum PASSWORD_FILE_EXPORT computeSha256Sum(const unsigned char *buffer, std::size_t size);
std::uint32_t PASSWORD_FILE_EXPORT generateRandomNumber(std::uint32_t min, std::uint32_t max);

} // namespace OpenSsl
} // namespace Util

#endif // PASSWORD_FILE_UTIL_OPENSSL_H
