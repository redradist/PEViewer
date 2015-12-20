#-------------------------------------------------
#
# Project created by QtCreator 2015-12-19T19:01:34
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = GaphicPEfile
TEMPLATE = app

LIBS += -lAdvapi32
LIBS += -lkernel32

SOURCES += main.cpp\
        mainwindow.cpp \
    peloader.cpp

HEADERS  += mainwindow.h \
    peloader.h

FORMS    += mainwindow.ui
