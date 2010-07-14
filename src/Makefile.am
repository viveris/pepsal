AM_CFLAGS = -I$(top_srcdir)/include

bin_PROGRAMS = pepsal
pepsal_LDFLAGS= -lnfnetlink -lnetfilter_queue -lrt -lpthread -lm
pepsal_SOURCES= pep.c hashtable.c pepbuf.c pepqueue.c syntab.c
man_MANS = pepsal.1
EXTRA_DIST = $(man_MANS)
