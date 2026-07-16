QT += core gui widgets network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

TARGET = LicenseManager
#DEFINES += DEBUG

# ============================================================================
# Build mode: uncomment one of the following
# ============================================================================

# Mode 1: Use MAC address
#DEFINES += USE_MAC_ADDRESS

# Mode 2: Use machine unique ID (SHA-256) - default
DEFINES += USE_MACHINE_ID

# ============================================================================

# MinGW specific settings
win32:mingw {
    QMAKE_CXXFLAGS += -finput-charset=UTF-8
    QMAKE_CXXFLAGS += -fexec-charset=UTF-8
    DEFINES += UNICODE _UNICODE
}

# ============================================================================
# GMSSL platform auto-detect (Windows + Linux, ARM/x86_64)
# ============================================================================

# GMSSL 基础路径
GMSSL_BASE = $$PWD/gmssl

# Windows 平台
win32 {
    GMSSL_ROOT = $$GMSSL_BASE/win
    INCLUDEPATH += $$GMSSL_ROOT/include
    LIBS += -L$$GMSSL_ROOT/lib -lgmssl

    win32:mingw {
        GMSSL_DLL = $$GMSSL_ROOT/lib/libgmssl.dll
        QMAKE_POST_LINK += $$QMAKE_COPY $$shell_path($$GMSSL_DLL) $$shell_path($$DESTDIR) $$escape_expand(\\n\\t)
    }

    LIBS += -lole32 -loleaut32 -lwbemuuid -liphlpapi -ladvapi32 -lrpcrt4 -luser32 -lshell32
    DEFINES += _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN
}

# Linux 平台
unix:!macx {
    # 使用 shell 命令检测架构（更可靠）
    ARCH = $$system(uname -m)
    message("Detected architecture: $$ARCH")

    # 判断架构
    contains(ARCH, arm) {
        GMSSL_ROOT = $$GMSSL_BASE/arm
        message("Using ARM GMSSL")
    } else {
        contains(ARCH, aarch64) {
            GMSSL_ROOT = $$GMSSL_BASE/arm
            message("Using ARM64 GMSSL")
        } else {
            GMSSL_ROOT = $$GMSSL_BASE/x86_64
            message("Using x86_64 GMSSL")
        }
    }

    # 检查目录是否存在
    !exists($$GMSSL_ROOT) {
        message("Warning: $$GMSSL_ROOT not found!")
        # 尝试另一个目录
        GMSSL_ROOT = $$GMSSL_BASE/x86_64
        message("Fallback to: $$GMSSL_ROOT")
    }

    # 检查库文件是否存在
    !exists($$GMSSL_ROOT/lib/libgmssl.so) {
        message("Warning: libgmssl.so not found in $$GMSSL_ROOT/lib!")
    }

    INCLUDEPATH += $$GMSSL_ROOT/include
    LIBS += -L$$GMSSL_ROOT/lib -lgmssl
    LIBS += -lpthread -ldl

    message("GMSSL_ROOT: $$GMSSL_ROOT")
}

# ============================================================================
# Build output directories
# ============================================================================

CONFIG(release, debug|release) {
    DESTDIR = $$PWD/release
} else {
    DESTDIR = $$PWD/debug
}

# Sources
SOURCES += \
    src/configmanager.cpp \
    src/gmsslcrypto.cpp \
    src/keyconfigdialog.cpp \
    src/licensegenerator.cpp \
    src/licensevalidator.cpp \
    src/logmanager.cpp \
    src/main.cpp \
    src/mainwindow.cpp \
    src/machine_id.cpp

HEADERS += \
    src/configmanager.h \
    src/gmsslcrypto.h \
    src/keyconfigdialog.h \
    src/licensegenerator.h \
    src/licensevalidator.h \
    src/logmanager.h \
    src/mainwindow.h \
    src/machine_id.h

FORMS += \
    src/keyconfigdialog.ui \
    src/mainwindow.ui

RESOURCES += resources.qrc

contains(DEFINES, USE_MAC_ADDRESS) {
    message("Current mode: MAC address")
} else {
    message("Current mode: Machine unique ID (SHA-256)")
}

target.path = $$[QT_INSTALL_EXAMPLES]/LicenseManager
INSTALLS += target
MAKEFLAGS += -j4
