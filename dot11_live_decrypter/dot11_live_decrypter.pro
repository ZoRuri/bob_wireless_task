TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap\
    -lcrypto

SOURCES += \
    crypto.c \
    common.c \
    dot11_live_decrypter.c

HEADERS += \
    pcap.h \
    crypto.h \
    common.h \
    crctable.h \
    osdep/byteorder.h
