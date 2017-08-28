AC_PREREQ([2.60])
AC_INIT([libwallycore],[0.1])
AC_CONFIG_AUX_DIR([tools/build-aux])
AC_CONFIG_MACRO_DIR([tools/build-aux/m4])
AC_CONFIG_SRCDIR([src/mnemonic.h])
AC_CONFIG_HEADERS([src/config.h])
AC_CANONICAL_HOST
AH_TOP([#ifndef LIBWALLYCORE_CONFIG_H
#define LIBWALLYCORE_CONFIG_H])
AH_BOTTOM([#include "ccan_config.h"
#endif /*LIBWALLYCORE_CONFIG_H*/])

LDPATH_VAR=LD_LIBRARY_PATH
case $host_os in
*darwin*)
    is_osx="yes"
    LDPATH_VAR=DYLD_LIBRARY_PATH
    ;;
esac
AM_CONDITIONAL([IS_OSX], [test "x$is_osx" == "xyes"])
AC_SUBST([LDPATH_VAR])

AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_INIT([disable-static])

AC_PROG_CC

# Prefer gccs ar/ranlib as they handle flto files properly
AC_CHECK_PROG(HAVE_GCC_AR,gcc-ar,yes,no)
if test "x$HAVE_GCC_AR" == "xyes"; then
    AR=gcc-ar
    AC_SUBST([AR])
fi

AC_CHECK_PROG(HAVE_GCC_RANLIB,gcc-ranlib,yes,no)
if test "x$HAVE_GCC_RANLIB" == "xyes"; then
    RANLIB=gcc-ranlib
    AC_SUBST([RANLIB])
fi

GNU_SED=sed
AC_CHECK_PROG(HAVE_GSED,gsed,yes,no)
if test "x$HAVE_GSED" == "xyes"; then
  GNU_SED=gsed
else
    if test "x$is_osx" == "xyes"; then
        AC_MSG_ERROR([gsed must be available to build this library])
    fi
fi
AC_SUBST([GNU_SED])

#
# C facilities
#
AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[enable debugging (default: no)]),
    [debug=$enableval], [debug=no])
AC_ARG_ENABLE(coverage,
    AS_HELP_STRING([--enable-coverage],[enable code coverage (default: no)]),
    [coverage=$enableval], [coverage=no])

CFLAGS=`echo $CFLAGS | $GNU_SED -e 's/-O2//g' | $GNU_SED -e 's/-g//g'`

AC_C_BIGENDIAN()
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

AM_CFLAGS=
if test "x$debug" == "xyes"; then
    # Make debugging easier, leave assertions in
    AX_CHECK_COMPILE_FLAG([-O0], [AM_CFLAGS="$AM_CFLAGS -O0"])
    AX_CHECK_COMPILE_FLAG([-ggdb], [AM_CFLAGS="$AM_CFLAGS -ggdb"])
    AX_CHECK_LINK_FLAG([-O0], [LDFLAGS="$LDFLAGS -O0"])
    AX_CHECK_LINK_FLAG([-ggdb], [LDFLAGS="$LDFLAGS -ggdb"])
    if test "x$coverage" == "xyes"; then
        AX_CHECK_COMPILE_FLAG([-fprofile-arcs -ftest-coverage], [AM_CFLAGS="$AM_CFLAGS -fprofile-arcs -ftest-coverage"])
        AX_CHECK_LINK_FLAG([-lgcov], [LDFLAGS="$LDFLAGS -lgcov"])
    fi
else
    # Optimise and harden if we can
    AX_CHECK_COMPILE_FLAG([-O3], [AM_CFLAGS="$AM_CFLAGS -O3"])
    AX_CHECK_COMPILE_FLAG([-D_FORTIFY_SOURCE=1], [AM_CFLAGS="$AM_CFLAGS -D_FORTIFY_SOURCE=1"])
    AX_CHECK_COMPILE_FLAG([-fstack-protector-strong], [AM_CFLAGS="$AM_CFLAGS -fstack-protector-strong"])
    AX_CHECK_COMPILE_FLAG([-DNDEBUG=1], [AM_CFLAGS="$AM_CFLAGS -DNDEBUG=1"])
    AX_CHECK_LINK_FLAG([-O3], [LDFLAGS="$LDFLAGS -O3"])
    AX_CHECK_LINK_FLAG([-flto], [LDFLAGS="$LDFLAGS -flto"])
    AX_CHECK_LINK_FLAG([-flto], [AM_CFLAGS="$AM_CFLAGS -flto"])
    AX_CHECK_LINK_FLAG([-Wl,-z,relro], [LDFLAGS="$LDFLAGS -Wl,-z,relro"])
fi

# -flax-vector-conversions is needed for our arm assembly
AX_CHECK_COMPILE_FLAG([-flax-vector-conversions], [AM_CFLAGS="$AM_CFLAGS -flax-vector-conversions"])

AX_CHECK_COMPILE_FLAG([-Wall], [AM_CFLAGS="$AM_CFLAGS -Wall"])
AX_CHECK_COMPILE_FLAG([-Wextra], [AM_CFLAGS="$AM_CFLAGS -Wextra"])
AX_CHECK_COMPILE_FLAG([-Wpedantic], [AM_CFLAGS="$AM_CFLAGS -Wpedantic"])
AX_CHECK_COMPILE_FLAG([-Wcast-align], [AM_CFLAGS="$AM_CFLAGS -Wcast-align"])
AX_CHECK_COMPILE_FLAG([-Wnested-externs], [AM_CFLAGS="$AM_CFLAGS -Wnested-externs"])
AX_CHECK_COMPILE_FLAG([-Wshadow], [AM_CFLAGS="$AM_CFLAGS -Wshadow"])
AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [AM_CFLAGS="$AM_CFLAGS -Wstrict-prototypes"])
AX_CHECK_COMPILE_FLAG([-Wno-unused-function], [AM_CFLAGS="$AM_CFLAGS -Wno-unused-function"])
AX_CHECK_COMPILE_FLAG([-Wno-long-long], [AM_CFLAGS="$AM_CFLAGS -Wno-long-long"])
AX_CHECK_COMPILE_FLAG([-Wno-overlength-strings], [AM_CFLAGS="$AM_CFLAGS -Wno-overlength-strings"])
AX_CHECK_COMPILE_FLAG([-Wformat], [AM_CFLAGS="$AM_CFLAGS -Wformat"])
AX_CHECK_COMPILE_FLAG([-Wformat-security], [AM_CFLAGS="$AM_CFLAGS -Wformat-security"])
AX_CHECK_COMPILE_FLAG([-Wformat-nonliteral], [AM_CFLAGS="$AM_CFLAGS -Wformat-nonliteral"])
AX_CHECK_COMPILE_FLAG([-fno-strict-aliasing], [NOALIAS_CFLAGS="-fno-strict-aliasing"])
AC_SUBST([NOALIAS_CFLAGS])

# Under OSX the compiler accepts this flag but the linker then fails.
if test "x$is_osx" != "xyes"; then
    AX_CHECK_COMPILE_FLAG([-Wl,--whole-archive], [whole_archive=yes])
fi

# SWIG versions vary in generated code quality; skip warnings
SWIG_WARN_CFLAGS="-fno-strict-aliasing"
AX_CHECK_COMPILE_FLAG([-Wno-shadow], [SWIG_WARN_CFLAGS="$SWIG_WARN_CFLAGS -Wno-shadow"])
AX_CHECK_COMPILE_FLAG([-Wno-self-assign], [SWIG_WARN_CFLAGS="$SWIG_WARN_CFLAGS -Wno-self-assign"])
AX_CHECK_COMPILE_FLAG([-Wno-missing-field-initializers], [SWIG_WARN_CFLAGS="$SWIG_WARN_CFLAGS -Wno-missing-field-initializers"])
AC_SUBST([SWIG_WARN_CFLAGS])

AC_ARG_ENABLE(export-all,
    AS_HELP_STRING([--enable-export-all],[export all functions (for testing, default: no)]),
    [export_all=$enableval], [export_all=no])
AM_CONDITIONAL([EXPORT_ALL], [test "x$export_all" == "xyes"])

if test "x$export_all" != "xyes"; then
    AX_CHECK_COMPILE_FLAG([-fvisibility=hidden], [AM_CFLAGS="$AM_CFLAGS -fvisibility=hidden"])
fi

# Assume we have no unaligned access if cross-compiling
AC_RUN_IFELSE([AC_LANG_SOURCE([int main(void){static int a[2];return *((int*)(((char*)a)+1)) != 0;}])],
              [AC_DEFINE([HAVE_UNALIGNED_ACCESS], 1, [Define if we have unaligned access])],,[foo=1])

if test "x$is_osx" != "xyes"; then
    # Assume we are using gcc (i.e. have this attribute) if cross-compiling
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([extern int foo(int) __attribute__((weak)); int main(void){return 0;}])],
                      [AC_DEFINE([HAVE_ATTRIBUTE_WEAK], 1, [Define if we have __attribute__((weak))])])
fi

AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sys/mman.h>]],[[mmap(0,0,0,0,0,0)]])],
               [AC_DEFINE(HAVE_MMAP, 1, [Define if we have mmap])])

AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stdlib.h>]],[[return posix_memalign(NULL,0,0)]])],
               [AC_DEFINE(HAVE_POSIX_MEMALIGN, 1, [Define if we have posix_memalign])])

AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <string.h>]],[[int x[1]; memset_s(x, 1, 0, 1)]])],
               [AC_DEFINE(HAVE_MEMSET_S, 1, [Define if we have memset_s])])

AC_CHECK_HEADERS([byteswap.h])

AX_PTHREAD([ac_have_pthread=yes], [ac_have_pthread=no])
AM_CONDITIONAL([USE_PTHREAD], [test "x$ac_have_pthread" == "xyes"])
if test "x$ac_have_pthread" == "xyes"; then
    AC_DEFINE([HAVE_PTHREAD], 1, [Define if we have pthread support])
fi

#
# libsecp256k1
#
# FIXME: This is needed to force libtool to use all object files from secp.
#        We can only build secp properly by recursively invoking
#        configure/make, and can't include it as a noinst_ library. Libtool
#        assumes that such libraries will be installed along with our library
#        target and so won't force all object files in the library to be
#        included in ours - despite the fact that we are making a shared
#        library and linking to a static one. This is broken and we work
#        around it by hacking the whole-archive flags into the _LDADD variable
#        for wallycore.
#        Because automake tries to police its users very strictly and fails
#        hard when flags are passed in this way, we have to substitute the
#        flags here.
#        Because libtool both intercepts -Wl and arbitrarily re-orders its
#        command line inputs, we have to concoct a single expression to
#        enforce linking that cannot be split, hence the below expression.
LIBADD_SECP256K1="secp256k1/.libs/libsecp256k1.a"
if test "x$whole_archive" == "xyes"; then
    LIBADD_SECP256K1="-Wl,--whole-archive,secp256k1/.libs/libsecp256k1.a,--no-whole-archive"
fi
AC_SUBST([LIBADD_SECP256K1])

#
# Python facilities
#
AX_PYTHON_DEVEL([>= '2.7.0'])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != ""])
AM_CONDITIONAL([RUN_PYTHON_TESTS], [test "x$pythonexists" == "xyes"])

#
# SWIG
#
AC_PROG_SWIG

AC_ARG_ENABLE(swig-python,
    AS_HELP_STRING([--enable-swig-python],[enable the SWIG python interface (default: no)]),
    [swig_python=$enableval], [swig_python=no])
AM_CONDITIONAL([USE_SWIG_PYTHON], [test "x$swig_python" == "xyes"])

if test "x$swig_python" == "xyes"; then
    if test "x$pythonexists" != "xyes"; then
        AC_MSG_FAILURE([ERROR: No usable python was found for swig-python])
    fi
    SWIG_PYTHON
    AX_CHECK_COMPILE_FLAG([-DSWIG_PYTHON_BUILD=1], [AM_CFLAGS="$AM_CFLAGS -DSWIG_PYTHON_BUILD=1"])
fi

AC_ARG_ENABLE(swig-java,
    AS_HELP_STRING([--enable-swig-java],[enable the SWIG java (JNI) interface (default: no)]),
    [swig_java=$enableval], [swig_java=no])
AM_CONDITIONAL([USE_SWIG_JAVA], [test "x$swig_java" == "xyes"])

if test "x$swig_java" == "xyes"; then
    AX_JNI_INCLUDE_DIR
    for JNI_DIR in $JNI_INCLUDE_DIRS; do
        SWIG_JAVA_CPPFLAGS="$SWIG_JAVA_CPPFLAGS -I$JNI_DIR"
    done
    SWIG_JAVA_OPT="-java"
    AC_SUBST([SWIG_JAVA_CPPFLAGS])
    AC_SUBST([SWIG_JAVA_OPT])
    AX_CHECK_COMPILE_FLAG([-DSWIG_JAVA_BUILD=1], [AM_CFLAGS="$AM_CFLAGS -DSWIG_JAVA_BUILD=1"])
fi

if test "x$JAVA_HOME" != "x"; then
    JAVA="$JAVA_HOME/bin/java"
    AC_SUBST([JAVA])
    JAVAC="$JAVA_HOME/bin/javac"
    AC_SUBST([JAVAC])
    JAR="$JAVA_HOME/bin/jar"
    AC_SUBST([JAR])
else
    AC_CHECK_PROGS(JAVA, [java])
    AC_CHECK_PROGS(JAVAC, [javac])
    AC_CHECK_PROGS(JAR, [jar])
fi
AM_CONDITIONAL([HAVE_JAVA], [test "x$JAVA" != "x"])
AM_CONDITIONAL([HAVE_JAVAC], [test "x$JAVAC" != "x"])
if test "x$swig_java" == "xyes"; then
    if test "x$JAVAC" != "x"; then
        if test "x$JAVA" != "x"; then
            # Only run tests if we have java-swig, compiler and interpreter
            run_java_tests="yes"
        fi
    fi
fi
AM_CONDITIONAL([RUN_JAVA_TESTS], [test "x$run_java_tests" != "x"])
JAVAC_TARGET=1.7
AC_SUBST([JAVAC_TARGET])

AC_SUBST([AM_CFLAGS])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])

secp_jni="--disable-jni"
if test "x$swig_java" == "xyes"; then
    secp_jni="--enable-jni"
fi
ac_configure_args="${ac_configure_args} --disable-shared ${secp_jni} --with-pic --with-bignum=no --enable-experimental --enable-module-schnorr --enable-module-ecdh --enable-openssl-tests=no --disable-dependency-tracking"
AC_CONFIG_SUBDIRS([src/secp256k1])


AC_OUTPUT
