dnl $Id$
dnl config.m4 for extension ebpf

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(ebpf, for ebpf support,
dnl Make sure that the comment is aligned:
dnl [  --with-ebpf             Include ebpf support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(ebpf, whether to enable ebpf support,
dnl Make sure that the comment is aligned:
[  --enable-ebpf           Enable ebpf support])

if test "$PHP_EBPF" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-ebpf -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/ebpf.h"  # you most likely want to change this
  dnl if test -r $PHP_EBPF/$SEARCH_FOR; then # path given as parameter
  dnl   EBPF_DIR=$PHP_EBPF
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for ebpf files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       EBPF_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$EBPF_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the ebpf distribution])
  dnl fi

  dnl # --with-ebpf -> add include path
  dnl PHP_ADD_INCLUDE($EBPF_DIR/include)


  AC_ARG_WITH([ebpf],
    [AS_HELP_STRING([--with-bcc=DIR], [Specify the path to bcc headers and libraries])],
    [LIB_BCC="$withval"],
    [LIB_BCC="deps/bcc"]
  )
  BCC_C_SOURCE="$LIB_BCC/src/cc"
  PHP_ADD_INCLUDE($BCC_C_SOURCE)
  AC_ARG_WITH([llvm],
   [AS_HELP_STRING([--with-llvm=DIR], [Specify the path to llvm headers and libraries])],
   [LIB_LLVM="$withval"],
   [LIB_LLVM="/usr/lib/llvm-14"]
  )

  CPPFLAGS="$CPPFLAGS -I$LIB_LLVM/include"

  AC_CHECK_HEADER([llvm/Config/llvm-config.h], [], [
    AC_MSG_ERROR([llvm/Config/llvm-config.h not found in $LIB_LLVM/include , Please install LLVM development headers, or specify the correct path with: --with-llvm=DIR (e.g. --with-llvm=/usr/lib/llvm-14) ])
  ])

  PHP_ADD_INCLUDE($LIB_LLVM/include)

  dnl AC_ARG_WITH([ebpf],
  dnl      [AS_HELP_STRING([--with-kernel=DIR], [Specify the path to llvm headers and libraries])],
  dnl      [LIB_KERNEL="$withval"],
  dnl      [LIB_KERNEL="/lib/modules/5.15.0-130-generic"]
  dnl )
  AC_DEFINE_UNQUOTED([KERNEL_MODULES_DIR], ["$LIB_KERNEL"], [Path to kernel modules])

  API_SOURCE="api"
  PHP_ADD_INCLUDE($API_SOURCE)

  PHP_ADD_LIBRARY_WITH_PATH(bcc, /usr/lib/x86_64-linux-gnu, EBPF_SHARED_LIBADD)

  dnl # --with-ebpf -> check for lib and symbol presence
  dnl LIBNAME=ebpf # you may want to change this
  dnl LIBSYMBOL=ebpf # you most likely want to change this

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $EBPF_DIR/$PHP_LIBDIR, EBPF_SHARED_LIBADD)

  dnl   AC_DEFINE(HAVE_EBPFLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong ebpf lib version or lib not found])
  dnl ],[
  dnl   -L$EBPF_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl

  PHP_SUBST(EBPF_SHARED_LIBADD)

  PHP_REQUIRE_CXX()
  PHP_ADD_LIBRARY(stdc++, 1, EBPF_SHARED_LIBADD)
  CXXFLAGS="$CXXFLAGS -Wall -Wno-unused-function -Wno-deprecated -Wno-deprecated-declarations -std=c++11"

  dnl PHP_NEW_EXTENSION(ebpf, ebpf.cpp, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)


  source_file="ebpf.cpp \
        $API_SOURCE/BPF.cc \
        $API_SOURCE/BPFTable.cc"

  PHP_NEW_EXTENSION(ebpf, $source_file, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)


fi
