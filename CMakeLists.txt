cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

# add project files
set(HEADER_FILES
    io/cryptoexception.h
    io/entry.h
    io/field.h
    io/parsingexception.h
    io/passwordfile.h
    util/openssl.h
    util/opensslrandomdevice.h
)
set(SRC_FILES
    io/cryptoexception.cpp
    io/entry.cpp
    io/field.cpp
    io/parsingexception.cpp
    io/passwordfile.cpp
    util/openssl.cpp
    util/opensslrandomdevice.cpp
)
set(TEST_HEADER_FILES

)
set(TEST_SRC_FILES
    tests/cppunit.cpp
    tests/passwordfiletests.cpp
)

# meta data
set(META_PROJECT_NAME passwordfile)
set(META_PROJECT_VARNAME PASSWORD_FILE)
set(META_APP_NAME "Passwordfile library")
set(META_APP_AUTHOR "Martchus")
set(META_APP_URL "https://github.com/${META_APP_AUTHOR}/${META_PROJECT_NAME}")
set(META_APP_DESCRIPTION "C++ library to read/write passwords from/to encrypted files.")
set(META_VERSION_MAJOR 3)
set(META_VERSION_MINOR 1)
set(META_VERSION_PATCH 1)

# find c++utilities
find_package(c++utilities 3.3.0 REQUIRED)
use_cpp_utilities()

# find zlib
find_package(ZLIB REQUIRED)
include_directories(${ZLIB_INCLUDE_DIRS})
list(APPEND LIBRARIES ${ZLIB_LIBRARIES})

# find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
list(APPEND LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})

# include modules to apply configuration
include(BasicConfig)
include(WindowsResources)
include(LibraryTarget)
include(TestTarget)
