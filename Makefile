# Makefile -- makefile for pam_chk program.
# Author: Luis Colorado <luiscoloradourcola@gmail.com>
# Date: Wed Dec 21 14:49:20 EET 2016

targets	= pam_chk pam_show.so
TOCLEAN += $(targets)

RM	?= rm -f
INSTALL	?= install -o `id -u` -g `id -g`
DMOD	?= -m 0755
XMOD	?= -m 0711

prefix	?= $(HOME)
bindir	?= $(prefix)/bin

pam_chk_objs = main.o conv.o
SOURCES += $(pam_chk_objs:.o=.c)
TOCLEAN += $(pam_chk_objs)
pam_chk_libs = -lpam

.PHONY: all clean install deinstall

all: $(targets)

clean:
	$(RM) $(TOCLEAN)

install:
	-$(INSTALL) -m $(DMOD) -d $(bindir)
	-$(INSTALL) -m $(XMOD) pam_chk $(bindir)/pam_chk

deinstall:
	-$(RM) $(bindir)/pam_chk 

pam_chk: $(pam_chk_objs)
	$(CC) $(LDFLAGS) -o $@ $(pam_chk_objs) $(pam_chk_libs)

pam_show.so_objs = pam_show.o
TOCLEAN += $(pam_show.so_objs)
pam_show.so_libs = -lpam -lc

pam_show.so: $(pam_show.so_objs)
	$(LD) $(LDFLAGS) -o $@ -shared $(pam_show.so_objs) $(pam_show.so_libs)

pam_show.o: pam_show.c
	$(CC) -fPIC -c $> -o $@

.depend: 
	$(CC) -MM $(SOURCES) > $@

-include .depend
