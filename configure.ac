
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
AC_SUBST(APXS)
AC_SUBST(V3LIB)
AC_SUBST(V3INCLUDE)
AC_CONFIG_FILES([\
	Makefile \
	build/apxs-wrapper \
])

#[chmod +x build/apxs-wrapper])

AC_PROG_CC
AC_OUTPUT
