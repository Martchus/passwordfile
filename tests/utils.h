#ifndef PASSWORDFILE_TESTS_UTILS_H
#define PASSWORDFILE_TESTS_UTILS_H

#include "../io/entry.h"
#include "../io/field.h"

#include <c++utilities/conversion/stringconversion.h>
#include <c++utilities/misc/traits.h>

#include <ostream>

namespace TestUtilities {

inline std::ostream &operator<<(std::ostream &out, const Io::Entry *entry)
{
    return out << ConversionUtilities::joinStrings(entry->path(), "/");
}

inline std::ostream &operator<<(std::ostream &out, const Io::Field *field)
{
    return out << field->name() << '=' << field->value();
}

} // namespace TestUtilities

#endif // PASSWORDFILE_TESTS_UTILS_H
