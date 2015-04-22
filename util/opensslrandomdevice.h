#ifndef OPENSSLRANDOMDEVICE_H
#define OPENSSLRANDOMDEVICE_H

#include <c++utilities/conversion/types.h>
#include <c++utilities/application/global.h>

namespace Util {

class LIB_EXPORT OpenSslRandomDevice
{
public:
    OpenSslRandomDevice();
    uint32 operator()() const;
    bool status() const;
};

}

#endif // OPENSSLRANDOMDEVICE_H
