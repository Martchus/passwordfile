projectname = passwordfile
appname = "Passwordfile library"
appauthor = Martchus
QMAKE_TARGET_DESCRIPTION = "C++ library to read/write passwords from/to encrypted files."
VERSION = 3.0.0

# include ../../common.pri when building as part of a subdirs project; otherwise include general.pri
!include(../../common.pri) {
    !include(./general.pri) {
        error("Couldn't find the common.pri or the general.pri file!")
    }
}

TEMPLATE = lib
CONFIG -= qt
CONFIG += shared

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
    LICENSE

# libs and includepath
CONFIG(debug, debug|release) {
    LIBS += -lc++utilitiesd
} else {
    LIBS += -lc++utilities
}
# TODO: remove build environment specific paths
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

# installs
mingw-w64-install {
    target.path = $$(INSTALL_ROOT)
    target.extra = install -m755 -D $${OUT_PWD}/release/lib$(TARGET).a $$(INSTALL_ROOT)/lib/lib$(TARGET).a
    INSTALLS += target
    dlltarget.path = $$(INSTALL_ROOT)
    dlltarget.extra = install -m755 -D $${OUT_PWD}/release/$(TARGET) $$(INSTALL_ROOT)/bin/$(TARGET)
    INSTALLS += dlltarget
} else {
    target.path = $$(INSTALL_ROOT)/lib
    INSTALLS += target
}
for(dir, $$list(io util)) {
    eval(inc_$${dir} = $${dir})
    inc_$${dir}.path = $$(INSTALL_ROOT)/include/$$projectname/$${dir}
    inc_$${dir}.files = $${dir}/*.h
    INSTALLS += inc_$${dir}
}
