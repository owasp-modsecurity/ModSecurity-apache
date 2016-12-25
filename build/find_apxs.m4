# https://www.gnu.org/software/autoconf-archive/ax_prog_apache.html#ax_prog_apache
AC_DEFUN([FIND_APXS],[
AC_MSG_NOTICE(looking for Apache module support via DSO through APXS)
# Check if the user provided --with-axps
AC_ARG_WITH(apxs,
            [AS_HELP_STRING([[--with-apxs=FILE]],
                            [FILE is the path to apxs; defaults to "apxs".])],
[
  if test "$withval" = "yes"; then
    APXS=apxs
  else
    APXS="$withval"
  fi
])

if test -z "$APXS"; then
  for i in /usr/local/apache22/bin \
           /usr/local/apache2/bin \
           /usr/local/apache/bin \
           /usr/local/sbin \
           /usr/local/bin \
           /usr/sbin \
           /usr/bin;
  do
    if test -f "$i/apxs2"; then
      APXS="$i/apxs2"
      break
    elif test -f "$i/apxs"; then
      APXS="$i/apxs"
      break
    fi
  done
fi
if test -n "$APXS" -a "$APXS" != "no" -a -x "$APXS" ; then
    AC_MSG_NOTICE(found APXS at $APXS)
else
    AC_MSG_ERROR(couldn't find APXS)
fi
])

