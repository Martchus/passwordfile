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

# meta data
set(META_PROJECT_NAME passwordfile)
set(META_APP_NAME "Passwordfile library")
set(META_APP_AUTHOR "Martchus")
set(META_APP_URL "https://github.com/${META_APP_AUTHOR}/${META_PROJECT_NAME}")
set(META_APP_DESCRIPTION "C++ library to read/write passwords from/to encrypted files.")
set(META_VERSION_MAJOR 3)
set(META_VERSION_MINOR 1)
set(META_VERSION_PATCH 1)

# stringification of meta data
set(META_PROJECT_NAME_STR "\"${META_PROJECT_NAME}\"")
set(META_APP_NAME_STR "\"${META_APP_NAME}\"")
set(META_APP_AUTHOR_STR "\"${META_APP_AUTHOR}\"")
set(META_APP_URL_STR "\"${META_APP_URL}\"")
set(META_APP_DESCRIPTION_STR "\"${META_APP_DESCRIPTION}\"")
set(META_APP_VERSION ${META_VERSION_MAJOR}.${META_VERSION_MINOR}.${META_VERSION_PATCH})
set(META_APP_VERSION_STR "\"${META_APP_VERSION}\"")

# define project
project(${META_PROJECT_NAME})

# add configuration header
configure_file(
    "${PROJECT_SOURCE_DIR}/resources/config.h.in"
    "${PROJECT_BINARY_DIR}/resources/config.h"
)
include_directories("${PROJECT_BINARY_DIR}")

# add windows resource file
if(MINGW)
    # create windows rc file from template
    set(WINDOWS_EXT "dll")
    configure_file(
        "${PROJECT_SOURCE_DIR}/resources/windows.rc.in"
        "${PROJECT_BINARY_DIR}/resources/windows.rc"
    )
    # set windres as resource compiler
    set(RES_FILES "${PROJECT_BINARY_DIR}/resources/windows.rc")
    set(CMAKE_RC_COMPILER_INIT windres)
    set(CMAKE_RC_COMPILE_OBJECT "<CMAKE_RC_COMPILER> <FLAGS> -O coff <DEFINES> -i <SOURCE> -o <OBJECT>")
    enable_language(RC)
endif(MINGW)

# remove library prefix when building with mingw-w64 (just for consistancy with qmake)
if(MINGW)
    set(CMAKE_SHARED_LIBRARY_PREFIX "")
endif(MINGW)

# disable new ABI (can't catch ios_base::failure with new ABI)
add_definitions(
    -D_GLIBCXX_USE_CXX11_ABI=0
)

# executable and linking
add_library(${META_PROJECT_NAME} SHARED ${HEADER_FILES} ${SRC_FILES} ${RES_FILES} ${WINDOWS_ICON_PATH})
target_link_libraries(${META_PROJECT_NAME} c++utilities z crypto)
set_target_properties(${META_PROJECT_NAME} PROPERTIES
    VERSION ${META_VERSION_MAJOR}.${META_VERSION_MINOR}.${META_VERSION_PATCH}
    SOVERSION ${META_VERSION_MAJOR}
    CXX_STANDARD 11
)
if(MINGW)
    # enable static library when building with mingw-w64
    add_library(${META_PROJECT_NAME}_static STATIC ${HEADER_FILES} ${SRC_FILES} ${RES_FILES} ${WINDOWS_ICON_PATH})
    set_target_properties(${META_PROJECT_NAME}_static PROPERTIES
        VERSION ${META_VERSION_MAJOR}.${META_VERSION_MINOR}.${META_VERSION_PATCH}
        SOVERSION ${META_VERSION_MAJOR}
        OUTPUT_NAME ${META_PROJECT_NAME}
        CXX_STANDARD 11
    )
endif(MINGW)

# add install target
install(TARGETS ${META_PROJECT_NAME}
    RUNTIME DESTINATION bin
    COMPONENT binary
    LIBRARY DESTINATION lib
    COMPONENT binary
    ARCHIVE DESTINATION lib
    COMPONENT binary
)
if(MINGW)
    install(TARGETS ${META_PROJECT_NAME}_static
        RUNTIME DESTINATION bin
        COMPONENT binary
        LIBRARY DESTINATION lib
        COMPONENT binary
        ARCHIVE DESTINATION lib
        COMPONENT binary
    )
endif(MINGW)
foreach(HEADER_FILE ${HEADER_FILES})
    get_filename_component(HEADER_DIR ${HEADER_FILE} DIRECTORY)
    install(
        FILES ${HEADER_FILE}
        DESTINATION include/${META_PROJECT_NAME}/${HEADER_DIR}
        COMPONENT header
    )
endforeach()
if(NOT TARGET install-binary)
    add_custom_target(install-binary
        DEPENDS ${META_PROJECT_NAME}
        COMMAND "${CMAKE_COMMAND}" -DCMAKE_INSTALL_COMPONENT=binary -P "${CMAKE_BINARY_DIR}/cmake_install.cmake"
    )
endif()
if(NOT TARGET install-header)
    add_custom_target(install-header
        DEPENDS ${META_PROJECT_NAME}
        COMMAND "${CMAKE_COMMAND}" -DCMAKE_INSTALL_COMPONENT=header -P "${CMAKE_BINARY_DIR}/cmake_install.cmake"
    )
endif()
if(NOT TARGET install-mingw-w64)
    add_custom_target(install-mingw-w64
        DEPENDS install-binary install-header
    )
endif()
if(NOT TARGET install-binary-strip)
    add_custom_target(install-binary-strip
        DEPENDS ${META_PROJECT_NAME}
        COMMAND "${CMAKE_COMMAND}" -DCMAKE_INSTALL_DO_STRIP=1 -DCMAKE_INSTALL_COMPONENT=binary -P "${CMAKE_BINARY_DIR}/cmake_install.cmake"
    )
endif()
if(NOT TARGET install-mingw-w64-importlib-strip)
    add_custom_target(install-mingw-w64-importlib-strip
        DEPENDS install-binary-strip
        COMMAND "${CMAKE_FIND_ROOT_PATH}/bin/strip" --strip-unneeded "${CMAKE_INSTALL_PREFIX}/lib/lib${META_PROJECT_NAME}.dll.a"
    )
endif()
if(NOT TARGET install-mingw-w64-staticlib-strip)
    add_custom_target(install-mingw-w64-staticlib-strip
        DEPENDS install-binary-strip
        COMMAND "${CMAKE_FIND_ROOT_PATH}/bin/strip" -g "${CMAKE_INSTALL_PREFIX}/lib/lib${META_PROJECT_NAME}.a"
    )
endif()
if(NOT TARGET install-mingw-w64-strip)
    add_custom_target(install-mingw-w64-strip
        DEPENDS install-binary-strip install-mingw-w64-importlib-strip install-mingw-w64-staticlib-strip install-header
    )
endif()
