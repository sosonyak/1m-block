TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.c

LIBS += -lnetfilter_queue
LIBS += -lsqlite3
