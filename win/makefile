# Copyright (C) 1999-2006, Index Data ApS
# All rights reserved.
# $Id: makefile,v 1.11 2007-01-11 12:21:25 adam Exp $

###########################################################
############### Parameters 
###########################################################

DEBUG=0   # 0 for release, 1 for debug

# YAZ and YAZ++
YAZ_DIR=..\..\yaz
YAZPP_DIR=..\..\yazpp

# iconv charcter conversion utility
HAVE_ICONV=1
ICONV_DIR=\iconv-1.9.2.win32

# libxslt
HAVE_LIBXSLT=1
LIBXSLT_DIR=\libxslt-1.1.17.win32

# libxml2 (used by libxslt)
HAVE_LIBXML2=1
LIBXML2_DIR=\libxml2-2.6.26.win32

# zlib compression (used by libxml2)
ZLIB_DIR=\zlib-1.2.3.win32

# get WIN32 binaries for libxslt, libxml, iconv, zlib from here:
# http://www.zlatkovic.com/libxml.en.html

default: all

all: dirs dll proxy iconv libxml2 libxslt yaz yazpp

NSIS="c:\program files\nsis\makensis-bz2.exe"

nsis: all
	$(NSIS) yazpp.nsi

nsishelp:
	$(NSIS)

# The current directory is supposed to be something like
# ..../yaz/win, everything is relative to that
ROOTDIR=..   # The home of yaz++

INCLDIR=$(ROOTDIR)\include  # our includes
LIBDIR=$(ROOTDIR)\lib       # We produce .lib, .exp etc there
BINDIR=$(ROOTDIR)\bin       # We produce exes and dlls there
WINDIR=$(ROOTDIR)\win       # all these Win make things
SRCDIR=$(ROOTDIR)\src       # for the case we move them under src
PROXYDIR=$(ROOTDIR)\proxy
ZOOMDIR=$(ROOTDIR)\zoom

!if $(DEBUG)
OBJDIR=$(WINDIR)\dobj       # where we store intermediate files
!else
OBJDIR=$(WINDIR)\obj        # where we store intermediate files
!endif

TMPDIR=$(ROOTDIR)\win\tmp
TMP=$(TMPDIR)

YAZPROXY_DLL=$(BINDIR)\yazproxy.dll
YAZPROXY_IMPLIB=$(LIBDIR)\yazproxy.lib

YAZPROXY=$(BINDIR)\yazproxy.exe

# shortcut names defined here
dll: $(YAZPROXY_DLL)
proxy: $(YAZPROXY)

!if $(DEBUG)
YAZD=yazd
YAZPPD=yazpp_1_d
!else
YAZD=yaz
YAZPPD=yazpp_1
!endif

# YAZ includes & libs
YAZ_LIB="$(YAZ_DIR)\lib\$(YAZD).lib"
YAZ_DEF=/DYAZ_HAVE_XML2=1 /DYAZ_USE_NEW_LOG=1 /I"$(YAZ_DIR)\include"

# Copy yaz.dll to our bin
yaz: $(BINDIR)\$(YAZD).dll
$(BINDIR)\$(YAZD).dll: "$(YAZ_DIR)\bin\$(YAZD).dll"
  copy "$(YAZ_DIR)\bin\$(YAZD).dll" $(BINDIR)

# YAZ++ includes & libs
YAZPP_LIB="$(YAZPP_DIR)\lib\$(YAZPPD).lib"
YAZPP_DEF=/I"$(YAZPP_DIR)\include"

# Copy yazpp.dll to our bin
yazpp: $(BINDIR)\$(YAZPPD).dll
$(BINDIR)\$(YAZPPD).dll: "$(YAZPP_DIR)\bin\$(YAZPPD).dll"
  copy "$(YAZPP_DIR)\bin\$(YAZPPD).dll" $(BINDIR)

!if $(HAVE_ICONV)
ICONV_DEF= \
  /D HAVE_ICONV_H=1 \
  /I"$(ICONV_DIR)\include"
ICONV_LIB= \
  "$(ICONV_DIR)\lib\iconv.lib"
iconv: $(BINDIR)\iconv.dll

$(BINDIR)\iconv.dll:
  copy "$(ICONV_DIR)\bin\iconv.dll" $(BINDIR)
!else
ICONV_DEF= \
  /D HAVE_ICONV_H=0
ICONV_LIB=
iconv:

!endif

!if $(HAVE_LIBXML2)
LIBXML2_LIB="$(LIBXML2_DIR)\lib\libxml2.lib"
LIBXML2_DEF=/D HAVE_XML2=1 /I"$(LIBXML2_DIR)\include"
libxml2: $(BINDIR)\libxml2.dll $(BINDIR)\zlib1.dll

$(BINDIR)\libxml2.dll:
  copy "$(LIBXML2_DIR)\bin\libxml2.dll" $(BINDIR)

$(BINDIR)\zlib1.dll:
  copy "$(ZLIB_DIR)\bin\zlib1.dll" $(BINDIR)

!else
LIBXML2_LIB=
LIBXML2_DEF=/D HAVE_XML2=0
libxml2: 

!endif

!if $(HAVE_LIBXSLT)
LIBXSLT_LIB="$(LIBXSLT_DIR)\lib\libxslt.lib"
LIBXSLT_DEF=/D YAZ_HAVE_XSLT=1 /I"$(LIBXSLT_DIR)\include"
libxslt: $(BINDIR)\libxslt.dll $(BINDIR)\zlib1.dll

$(BINDIR)\libxslt.dll:
  copy "$(LIBXSLT_DIR)\bin\libxslt.dll" $(BINDIR)

!else
LIBXSLT_LIB=
LIBXSLT_DEF=/D YAZ_HAVE_XSLT=0
libxslt: 

!endif


### C and CPP compiler  (the same thing)
# Note: $(CPP) has already been defined in the environment
# (if you set things up right!)

COMMON_C_OPTIONS=          \
  /nologo /W3 /EHsc /FD /c \
  /D "_CRT_SECURE_NO_DEPRECATE" \
  $(ICONV_DEF)             \
  $(YAZ_DEF)               \
  $(YAZPP_DEF)             \
  $(LIBXML2_DEF)           \
  $(LIBXSLT_DEF)           \
  /D "_WINDOWS"            \
  /D "WIN32"               \
  /D "HAVE_WCHAR_H=1"      \
  /FR"$(OBJDIR)\\"         \
  /Fo"$(OBJDIR)\\"         \
  /Fd"$(OBJDIR)\\" 

COMMON_C_INCLUDES= \
  /I"$(ROOTDIR)\include"

DEBUG_C_OPTIONS=  \
  /D "_DEBUG"      \
  /MDd  /Od /Zi /Gm

RELEASE_C_OPTIONS=  \
  /D "NDEBUG"        \
  /MD /O2

# /W3  = warning level
# /EHsc= Enable exception handling
# /FD  = Generate file dependencies (what ever they are)
# /c   = compile without linking
# /FR  = Generate browse info (.sbr file that gets combined into .bsc)
# /Fo  = object file name (or at least path)
# /Fd  = debug database name (or path)
# /MD  = Runtime library: Multithread DLL
# /MDd = Runtime library: Multithread DLL (debug)
# /Od  = Disable optimising (debug)
# /O2  = Optimize for speed
# /Gm  = Minimal rebuild (some cpp class stuff)
# /Zi  = Program database for debuggers
# /ZI  = Pgm database with special "edit&continue" stuff - not available in C5


### Linker options
LINK=link.exe

LINK_LIBS=kernel32.lib user32.lib gdi32.lib advapi32.lib uuid.lib \
          wsock32.lib  advapi32.lib \
           $(YAZ_LIB) $(YAZPP_LIB) $(ICONV_LIB) $(LIBXML2_LIB) $(LIBXSLT_LIB)

COMMON_LNK_OPTIONS=\
		/nologo \
		/subsystem:windows \
		/machine:i386 \
		/incremental:no

DEBUG_LNK_OPTIONS= /debug 

RELEASE_LNK_OPTIONS=

DLL_LINK_OPTIONS= /dll  
CLIENT_LINK_OPTIONS = /subsystem:console  

# Final opt variables
!if $(DEBUG)
COPT=   $(COMMON_C_OPTIONS)   $(DEBUG_C_OPTIONS)     $(COMMON_C_INCLUDES)
MTLOPT= $(COMMON_MTL_OPTIONS) $(DEBUG_MTL_OPTIONS)
RCOPT=  $(COMMON_RC_OPTIONS)  $(DEBUG_RC_OPTIONS)
LNKOPT= $(COMMON_LNK_OPTIONS) $(DEBUG_LNK_OPTIONS)   $(LNK_LIBS)
TCLOPT= $(COMMON_TCL_OPTIONS)

!else
COPT=   $(COMMON_C_OPTIONS)   $(RELEASE_C_OPTIONS)   $(COMMON_C_INCLUDES) 
MTLOPT= $(COMMON_MTL_OPTIONS) $(RELEASE_MTL_OPTIONS)
RCOPT=  $(COMMON_RC_OPTIONS)  $(RELEASE_RC_OPTIONS)
LNKOPT= $(COMMON_LNK_OPTIONS) $(RELEASE_LNK_OPTIONS) $(LNK_LIBS)
TCLOPT= $(COMMON_TCL_OPTIONS)
!endif

# Source and object modules

YAZPROXY_OBJS= \
   "$(OBJDIR)\yaz-proxy-main.obj"

YAZPROXY_DLL_OBJS = \
   "$(OBJDIR)\yaz-proxy.obj" \
   "$(OBJDIR)\yaz-proxy-config.obj" \
   "$(OBJDIR)\yaz-usemarcon.obj" \
   "$(OBJDIR)\msg-thread.obj" \
   "$(OBJDIR)\charset-converter.obj" \
   "$(OBJDIR)\limit-connect.obj" \
   "$(OBJDIR)\modules.obj" \
   "$(OBJDIR)\yaz-bw.obj"

###########################################################
############### Compiling 
###########################################################

# Note: This defines where to look for the necessary
# source files. Funny way of doing it, but it works.

{$(SRCDIR)}.cpp{$(OBJDIR)}.obj:
	$(CPP) $(COPT) $< 

###########################################################
############### Resources
###########################################################

### The RC compiler (resource files)
RSC=rc.exe
COMMON_RC_OPTIONS= /l 0x406 /i"$(ROOTDIR)" 
DEBUG_RC_OPTIONS=/d "_DEBUG"
RELEASE_RC_OPTIONS=/d "NDEBUG"

!if $(DEBUG)
RSOPT=/d_DEBUG
!else
RSOPT=/d_NDEBUG
!endif

###########################################################
############### Linking
###########################################################

$(YAZPROXY_DLL) $(YAZPROXY_IMPLIB): "$(BINDIR)" $(YAZPROXY_DLL_OBJS)
	$(LINK) \
		$(LNKOPT)  \
		$(LINK_LIBS)  \
		$(DLL_LINK_OPTIONS) \
		$(YAZPP_IMPLIB) \
		$(YAZPROXY_DLL_OBJS) \
		/out:$(YAZPROXY_DLL)  \
		/implib:"$(YAZPROXY_IMPLIB)" \

$(YAZPROXY) : "$(BINDIR)" $(YAZPROXY_OBJS) $(YAZPROXY_IMPLIB)
	$(LINK) \
        	$(LNKOPT)  \
		$(CLIENT_LINK_OPTIONS) \
		$(LINK_LIBS)  \
		$(YAZPP_IMPLIB) \
		$(YAZPROXY_IMPLIB) \
		$(YAZPROXY_OBJS) \
		/out:$(YAZPROXY)

clean:
	-del $(BINDIR)\*.exe
	-del $(BINDIR)\*.dll
	-del $(TMPDIR)\*.
	-del $(LIBDIR)\*.LIB
	-del $(OBJDIR)\*.OBJ

realclean: clean

########### check directories and create if needed
dirs: $(OBJDIR) $(WINDIR) $(LIBDIR) $(BINDIR) $(TMPDIR)

$(OBJDIR) $(WINDIR) $(LIBDIR) $(BINDIR) $(TMPDIR):
	if not exist "$@/$(NUL)" mkdir "$@"

