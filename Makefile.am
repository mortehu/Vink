bin_PROGRAMS = vink

AM_CFLAGS = -Wall -std=c89 -pthread
AM_CPPFLAGS = -D_GNU_SOURCE

vink_SOURCES = \
  common.h \
  main.c \
  io.c io.h \
  arena.c arena.h \
  tree.c tree.h \
  server.c server.h \
  peer.c peer.h

vink_LDFLAGS = -lruli -lgnutls -lexpat
