cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

# set meta data
project(passwordfile)
set(META_PROJECT_NAME ${PROJECT_NAME})
set(META_PROJECT_VARNAME PASSWORD_FILE)
set(META_APP_NAME "Passwordfile library")
set(META_APP_AUTHOR "Martchus")
set(META_APP_URL "https://github.com/${META_APP_AUTHOR}/${META_PROJECT_NAME}")
set(META_APP_DESCRIPTION "C++ library to read/write passwords from/to encrypted files")
set(META_VERSION_MAJOR 5)
set(META_VERSION_MINOR 0)
set(META_VERSION_PATCH 6)
set(META_ADD_DEFAULT_CPP_UNIT_TEST_APPLICATION ON)

# add project files
set(HEADER_FILES
    io/cryptoexception.h
    io/entry.h
    io/field.h
    io/parsingexception.h
    io/passwordfile.h
    util/openssl.h
    util/opensslrandomdevice.h)
set(SRC_FILES
    io/cryptoexception.cpp
    io/entry.cpp
    io/field.cpp
    io/parsingexception.cpp
    io/passwordfile.cpp
    util/openssl.cpp
    util/opensslrandomdevice.cpp)
set(TEST_HEADER_FILES)
set(TEST_SRC_FILES tests/utils.h tests/passwordfiletests.cpp tests/entrytests.cpp tests/fieldtests.cpp
                   tests/opensslrandomdevice.cpp tests/opensslutils.cpp)

set(DOC_FILES README.md)

# find c++utilities
set(CONFIGURATION_PACKAGE_SUFFIX
    ""
    CACHE STRING "sets the suffix for find_package() calls to packages configured via c++utilities")
find_package(c++utilities${CONFIGURATION_PACKAGE_SUFFIX} 5.0.0 REQUIRED)
use_cpp_utilities(VISIBILITY PUBLIC)

# find 3rd party libraries
include(3rdParty)
use_zlib()
use_crypto()

# include modules to apply configuration
include(BasicConfig)
include(WindowsResources)
include(LibraryTarget)
include(TestTarget)
include(Doxygen)
include(ConfigHeader)
