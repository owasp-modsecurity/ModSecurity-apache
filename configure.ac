
AC_INIT([ModSecurity-Apache], [0.01],[support@modsecurity.org])
AC_PREREQ(2.68)
AC_CONFIG_SRCDIR([LICENSE])
AC_CONFIG_MACRO_DIR([build])
#AC_CONFIG_AUX_DIR([build])
# Show erors and do not conform to GNU standards
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
FIND_APXS()
FIND_LIBMOD()
AX_PROG_APACHE()
AC_PATH_PROGS(PERL, [perl perl5], )
AC_SUBST(APXS)
AC_SUBST(V3LIB)
AC_SUBST(V3INCLUDE)
AC_SUBST(APACHE)

# Some directories
MSC_BASE_DIR=`pwd`
MSC_PKGBASE_DIR="$MSC_BASE_DIR/.."
MSC_TEST_DIR="$MSC_BASE_DIR/tests"
MSC_REGRESSION_DIR="$MSC_TEST_DIR/regression"
MSC_REGRESSION_SERVERROOT_DIR="$MSC_REGRESSION_DIR/server_root"
MSC_REGRESSION_CONF_DIR="$MSC_REGRESSION_SERVERROOT_DIR/conf"
MSC_REGRESSION_LOGS_DIR="$MSC_REGRESSION_SERVERROOT_DIR/logs"
MSC_REGRESSION_DOCROOT_DIR="$MSC_REGRESSION_SERVERROOT_DIR/htdocs"

if test -f /etc/apache2/envvars
then
    SERVER_MPM=`. /etc/apache2/envvars && $APACHE -V | grep Server\ MPM | awk '{print $3}'`
    SERVER_MPM_MODE=`. /etc/apache2/envvars && $APACHE -M | grep mpm_${SERVER_MPM}_module | awk '{print $2}' | sed -e 's/@<:@\@{:@\@:}@@:>@//g'`
    SERVER_AUTHZ_MODE=`. /etc/apache2/envvars && $APACHE -M | grep authz_core_module | awk '{print $2}' | sed -e 's/@<:@\@{:@\@:}@@:>@//g'`
else
    SERVER_MPM=`$APACHE -V | grep Server\ MPM | awk '{print $3}'`
    SERVER_MPM_MODE=`$APACHE -M | grep mpm_${SERVER_MPM}_module | awk '{print $2}' | sed -e 's/@<:@\@{:@\@:}@@:>@//g'`
    SERVER_AUTHZ_MODE=`$APACHE -M | grep authz_core_module | awk '{print $2}' | sed -e 's/@<:@\@{:@\@:}@@:>@//g'`
fi

AC_SUBST(MSC_BASE_DIR)
AC_SUBST(MSC_PKGBASE_DIR)
AC_SUBST(MSC_TEST_DIR)
AC_SUBST(MSC_REGRESSION_DIR)
AC_SUBST(MSC_REGRESSION_SERVERROOT_DIR)
AC_SUBST(MSC_REGRESSION_CONF_DIR)
AC_SUBST(MSC_REGRESSION_LOGS_DIR)
AC_SUBST(MSC_REGRESSION_DOCROOT_DIR)

AC_SUBST(SERVER_MPM)
AC_SUBST(SERVER_MPM_MODE)
AC_SUBST(SERVER_AUTHZ_MODE)

echo "Found Apache with MPM ${SERVER_MPM}, ${SERVER_MPM_MODE}."

APXS_SBINDIR="`$APXS -q SBINDIR`"
APXS_PROGNAME="`$APXS -q PROGNAME`"

APXS_HTTPD="$APXS_SBINDIR/$APXS_PROGNAME"
AC_SUBST(APXS_HTTPD)
APXS_LIBEXECDIR="`$APXS -q LIBEXECDIR`"
if test "xx$APXS_LIBEXECDIR" = "xx"; then APXS_LIBEXECDIR="`$APXS -q LIBDIR`/modules"; fi
AC_SUBST(APXS_LIBEXECDIR)

# generating apache depends loadable modules
# authz_core required, if not static
# one mpm required, if not static
echo "" > t/conf/modules.conf

if @<:@ ${SERVER_AUTHZ_MODE} == "shared" @:>@; then
    echo "LoadModule authz_core_module ${APXS_LIBEXECDIR}/mod_authz_core.so" >> t/conf/modules.conf
fi
if @<:@ ${SERVER_MPM_MODE} == "shared" @:>@; then
    echo "LoadModule mpm_${SERVER_MPM}_module ${APXS_LIBEXECDIR}/mod_mpm_${SERVER_MPM}.so" >> t/conf/modules.conf
fi
echo "" >> t/conf/modules.conf


AC_CONFIG_FILES([\
	Makefile \
	build/apxs-wrapper \
	tests/regression/server_root/conf/httpd.conf \
	tests/regression/misc/40-secRemoteRules.t \
	tests/regression/misc/60-pmfromfile-external.t \
	tests/regression/misc/50-ipmatchfromfile-external.t \
	tests/run-regression-tests.pl
])

#[chmod +x build/apxs-wrapper])

AC_PROG_CC
AC_OUTPUT
