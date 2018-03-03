#KVER   ?= $(shell uname -r)
#KVER   ?= 4.4.32+
#KDIR   ?= /lib/modules/$(KVER)/build/
KDIR   ?= /usr/src/linux/
DEPMOD  = /sbin/depmod -a
CC     ?= gcc
obj-m   = xt_NATMAP.o
CFLAGS_xt_NATMAP.o := -DDEBUG

all: xt_NATMAP.ko libxt_NATMAP.so

xt_NATMAP.ko: version.h xt_NATMAP.c xt_NATMAP.h
	make -C $(KDIR) M=$(CURDIR) modules CONFIG_DEBUG_INFO=y
	-sync

%_sh.o: libxt_NATMAP.c xt_NATMAP.h
	gcc -O2 -Wall -Wunused -fPIC -o $@ -c $<
	#$

%.so: %_sh.o
	gcc -shared -o $@ $<

sparse: clean | version.h xt_NATMAP.c xt_NATMAP.h
	make -C $(KDIR) M=$(CURDIR) modules C=1

cppcheck:
	cppcheck -I $(KDIR)/include --enable=all --inconclusive xt_NATMAP.c
	cppcheck libxt_NATMAP.c

coverity:
	coverity-submit -v

version.h: xt_NATMAP.c xt_NATMAP.h Makefile
	@./version.sh --define > version.h

clean:
	make -C $(KDIR) M=$(CURDIR) clean
	-rm -f *.so *_sh.o *.o modules.order

install: | minstall linstall

minstall: | xt_NATMAP.ko
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)

linstall: libxt_NATMAP.so
	install -D $< $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/$<

uninstall:
	-rm -f $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/libxt_NATMAP.so
	-rm -f $(KDIR)/extra/xt_NATMAP.ko

.PHONY: all minstall linstall install uninstall clean cppcheck
