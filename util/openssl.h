#ifndef OPENSSL_H
#define OPENSSL_H

#include "../global.h"

namespace Util {

namespace OpenSsl {

void PASSWORD_FILE_EXPORT init();
void PASSWORD_FILE_EXPORT clean();
}
}

#endif // OPENSSL_H
