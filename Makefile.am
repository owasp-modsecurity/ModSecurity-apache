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
	t/logs/* \
	t/htdocs/index.html \
	t/conf/extra.conf \
	t/conf/apache_test_config.pm \
	t/conf/httpd.conf \
	src/*.lo \
	src/*.slo

CLEANDIRECTORIES = \
	t/logs


all:
	chmod +x build/apxs-wrapper
	build/apxs-wrapper

test:
	cd t/ && ./TEST


install-exec-hook: $(pkglib_LTLIBRARIES)
	@APXS@ -i -n mod_security3 ./src/.libs/mod_security3.so


.PHONY: all
