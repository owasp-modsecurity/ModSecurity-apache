# https://www.gnu.org/software/autoconf-archive/ax_prog_apache.html#ax_prog_apache
AC_DEFUN([FIND_LIBMOD],[
AC_MSG_NOTICE(looking for libmodsecurity)
# Check if the user provided --with-libmodsecurity
AC_ARG_WITH(libmodsecurity,
            [AS_HELP_STRING([[--with-libmodsecurity=FILE]],
                            [FILE is the path to libmodsecurity install dir; defaults to "/usr/local/modsecurity/".])],
[
  if test "$withval" = "yes"; then
    V3PATH=/usr/local/modsecurity/
  else
    V3PATH="$withval"
    if test -f "${V3PATH}lib/libmodsecurity.so"; then
      V3LIB="${V3PATH}lib/"
    fi
  fi
])

if test -z "$V3PATH"; then
  for i in /usr/local/modsecurity/ \
           /usr/local/sbin \
           /usr/local/bin \
           /usr/sbin \
           /usr/bin \
           /usr;
  do
    if test -f "$i/lib/libmodsecurity.so"; then
      V3LIB="$i/lib/"
    fi
    if test -f "$i/lib64/libmodsecurity.so"; then
      V3LIB="$i/lib64/"
    fi
    if test -f "$i/include/modsecurity/modsecurity.h"; then
      V3INCLUDE="$i/include/"
      # TODO: test if V3LIB is set
      break
    fi  
  done
fi
if test -n "$V3LIB" -a "$V3LIB" != "no" -a -x "$V3LIB" ; then
    AC_MSG_NOTICE(found libmodsecurity at $V3LIB)
else
    AC_MSG_ERROR(couldn't find libmodsecurity)
fi
])

