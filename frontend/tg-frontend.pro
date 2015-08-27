SOURCES	+= main.cpp \
	md5.c \
        trayicon.cpp \
        trayicon_x11.cpp
HEADERS	+= main.h \
	   trayicon.h
unix {
  UI_DIR = .ui
  MOC_DIR = .moc
  OBJECTS_DIR = .obj
}
FORMS	= ask.ui
TEMPLATE	=app
CONFIG	+= qt warn_on release
LANGUAGE	= C++
DESTDIR = /usr/local/bin
QMAKE_CXXFLAGS_WARN_ON = -Wno-non-virtual-dtor
