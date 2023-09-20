QT = core

CONFIG += c++17 cmdline
LIBS += -L../lib -llibssh2 -lcrypt32 -lbcrypt -lWs2_32

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        cdirecttcpip.cpp \
        main.cpp

HEADERS += \
    cdirecttcpip.h

INCLUDEPATH += \
    ../include
