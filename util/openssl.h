#ifndef PASSWORD_FILE_UTIL_OPENSSL_H
#define OPENSSL_H

#include "../global.h"

namespace Util {

namespace OpenSsl {

void PASSWORD_FILE_EXPORT init();
void PASSWORD_FILE_EXPORT clean();
} // namespace OpenSsl
} // namespace Util

#endif // PASSWORD_FILE_UTIL_OPENSSL_H
