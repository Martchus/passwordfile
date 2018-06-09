#ifndef OPENSSLRANDOMDEVICE_H
#define OPENSSLRANDOMDEVICE_H

#include "../global.h"

#include <c++utilities/conversion/types.h>

#include <limits>

namespace Util {

class PASSWORD_FILE_EXPORT OpenSslRandomDevice {
public:
    using result_type = uint32;

    OpenSslRandomDevice();
    uint32 operator()() const;
    bool status() const;
    static constexpr result_type min();
    static constexpr result_type max();
};

constexpr OpenSslRandomDevice::result_type OpenSslRandomDevice::min()
{
    return std::numeric_limits<result_type>::min();
}

constexpr OpenSslRandomDevice::result_type OpenSslRandomDevice::max()
{
    return std::numeric_limits<result_type>::max();
}

} // namespace Util

#endif // OPENSSLRANDOMDEVICE_H
