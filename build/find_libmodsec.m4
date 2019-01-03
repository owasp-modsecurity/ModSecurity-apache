# https://www.gnu.org/software/autoconf-archive/ax_prog_apache.html#ax_prog_apache
AC_DEFUN([FIND_LIBMOD],[
AC_MSG_NOTICE(looking for libmodsecurity)
# Check if the user provided --with-libmodsecurity
AC_ARG_WITH(libmodsecurity,
            [AS_HELP_STRING([[--with-libmodsecurity=FILE]],
                            [FILE is the path to libmodsecurity install dir; defaults to "/usr/local/modsecurity/".])],
[
  if test "$withval" = "yes"; then
    AC_SUBST(CPPFLAGS, "$CPPFLAGS -I/usr/local/modsecurity/include/ -L/usr/local/modsecurity/lib/")
    V3INCLUDE="/usr/local/modsecurity/include/"
    V3LIB="/usr/local/modsecurity/lib/"
  else
    AC_SUBST(CPPFLAGS, "$CPPFLAGS -I${withval}/include/ -L${withval}/lib/")
    V3INCLUDE="${withval}/include/"
    V3LIB="${withval}/lib/"
  fi
])

dnl Check the ModSecurity libraries (modsecurity)

AC_CHECK_LIB([modsecurity], [msc_init], [
        AC_DEFINE([HAVE_MODSECURITYLIB], [1],
                [Define to 1 if you have the `libmodsecurity' library (-lmodsecurity).])], [
        AC_MSG_ERROR([ModSecurity libraries not found!])])

AC_CHECK_HEADERS([modsecurity/modsecurity.h], [], [
        AC_MSG_ERROR([ModSecurity headers not found...])])
])

