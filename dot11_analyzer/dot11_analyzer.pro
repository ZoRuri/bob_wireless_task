#-------------------------------------------------
#
# Project created by QtCreator 2017-01-20T04:38:47
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = dot11_analyzer
TEMPLATE = app

LIBS += -ltins\
    -lpcap

CONFIG += console c++11

SOURCES += main.cpp\
        mainwindow.cpp \
    capture.cpp \
    interfacedialog.cpp

HEADERS  += mainwindow.h \
    capture.h \
    interfacedialog.h

FORMS    += mainwindow.ui \
    interfacedialog.ui

RESOURCES += \
    icon_image/icon_image.qrc
