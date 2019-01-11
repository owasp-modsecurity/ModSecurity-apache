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
	t/conf/httpd.conf \
	t/conf/apache_test_config.pm \
	t/conf/httpd.conf \
	t/conf/mime.types \
	t/conf/modules.conf \
	src/*.lo \
	src/*.slo \
	src/*.o \
	src/*.so \
	src/.libs/*.so


CLEANDIRECTORIES = \
	t/logs \
	src/.libs


all:
	chmod +x build/apxs-wrapper
	build/apxs-wrapper

test:
	cd t/ && ./TEST -clean
	cd t/ && ./TEST -configure
	cd t/ && ./TEST -httpd_conf conf/httpd.conf -httpd @APACHE@ -apxs @APXS@


install-exec-hook: $(pkglib_LTLIBRARIES)
	@APXS@ -i -n mod_security3 ./src/.libs/mod_security3.so


.PHONY: all
