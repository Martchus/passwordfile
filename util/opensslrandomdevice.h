#ifndef OPENSSLRANDOMDEVICE_H
#define OPENSSLRANDOMDEVICE_H

#include "../global.h"

#include <c++utilities/conversion/types.h>

namespace Util {

class PASSWORD_FILE_EXPORT OpenSslRandomDevice
{
public:
    OpenSslRandomDevice();
    uint32 operator()() const;
    bool status() const;
};

}

#endif // OPENSSLRANDOMDEVICE_H
