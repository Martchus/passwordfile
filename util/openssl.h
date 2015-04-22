#ifndef OPENSSL_H
#define OPENSSL_H

#include <c++utilities/application/global.h>

namespace Util {

namespace OpenSsl {

void LIB_EXPORT init();
void LIB_EXPORT clean();

}

}

#endif // OPENSSL_H
