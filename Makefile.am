ACLOCAL_AMFLAGS = -I build

MAINTAINERCLEANFILES = \
	config.log \
        Makefile.in \
        aclocal.m4 \
        compile \
        configure \
        install-sh \
        missing \
        modsec-shared-collections \
        modsec-shared-collections-lock

CLEANFILES = \
	t/logs \
	t/conf


all:
	chmod +x build/apxs-wrapper
	build/apxs-wrapper

test:
	cd t/ && ./TEST.PL

.PHONY: all
