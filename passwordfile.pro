projectname = passwordfile

# include ../../common.pri when building as part of a subdirs project; otherwise include general.pri
!include(../../common.pri) {
    !include(./general.pri) {
        error("Couldn't find the common.pri or the general.pri file!")
    }
}

TEMPLATE = lib
CONFIG -= qt
win32 {
    CONFIG += dll
}

# files
SOURCES += aes/aes.cpp \
    io/cryptoexception.cpp \
    io/entry.cpp \
    io/field.cpp \
    io/parsingexception.cpp \
    io/passwordfile.cpp \
    util/opensslrandomdevice.cpp \
    util/openssl.cpp


HEADERS  += aes/aes.h \
    io/cryptoexception.h \
    io/entry.h \
    io/field.h \
    io/parsingexception.h \
    io/passwordfile.h \
    util/opensslrandomdevice.h \
    util/openssl.h

OTHER_FILES += \
    README.md \
    LICENSE \
    pkgbuild/default/PKGBUILD \
    pkgbuild/mingw-w64/PKGBUILD

# libs and includepath
CONFIG(debug, debug|release) {
    LIBS += -L../../ -lc++utilitiesd
} else {
    LIBS += -L../../ -lc++utilities
}
win32 {
    contains(QMAKE_TARGET.arch, x86_64):{
        LIBS += -L../../../openssl-mingw_amd64/lib/ -lcrypto
        INCLUDEPATH += ../../../build/openssl-mingw_amd64/include
    } else {
        LIBS += -L../../../openssl-mingw_i386/lib/ -lcrypto
        INCLUDEPATH += ../../../build/openssl-mingw_i386/include
    }
} else {
    android {
        LIBS += -L/opt/android-openssl/usr/lib/ -lcrypto
        INCLUDEPATH += /opt/android-openssl/usr/include
        ANDROID_PACKAGE_SOURCE_DIR = $$PWD/android
        ANDROID_EXTRA_LIBS = /opt/android-openssl/usr/lib/libcrypto.so
    } else {
        LIBS += -lcrypto
    }
}
LIBS += -lz
INCLUDEPATH += ../

# installs
!android {
    target.path = $$(INSTALL_ROOT)/lib
    INSTALLS += target
    for(dir, $$list(io util)) {
        eval(inc_$${dir} = $${dir})
        inc_$${dir}.path = $$(INSTALL_ROOT)/include/$$projectname/$${dir}
        inc_$${dir}.files = $${dir}/*.h
        INSTALLS += inc_$${dir}
    }
}
