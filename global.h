// Created via CMake from template global.h.in
// WARNING! Any changes to this file will be overwritten by the next CMake run!

#ifndef PASSWORD_FILE_GLOBAL
#define PASSWORD_FILE_GLOBAL

#include "passwordfile-devel-definitions.h"
#include <c++utilities/application/global.h>

#ifdef PASSWORD_FILE_STATIC
#define PASSWORD_FILE_EXPORT
#define PASSWORD_FILE_IMPORT
#else
#define PASSWORD_FILE_EXPORT CPP_UTILITIES_GENERIC_LIB_EXPORT
#define PASSWORD_FILE_IMPORT CPP_UTILITIES_GENERIC_LIB_IMPORT
#endif

/*!
 * \def PASSWORD_FILE_EXPORT
 * \brief Marks the symbol to be exported by the passwordfile library.
 */

/*!
 * \def PASSWORD_FILE_IMPORT
 * \brief Marks the symbol to be imported from the passwordfile library.
 */

#endif // PASSWORD_FILE_GLOBAL
