EXTRA_DIST = PKG-INFO README pyaff.c setup.py

if HAVE_PYTHON
AM_CFLAGS		= -I$(top_srcdir)/lib -include affconfig.h

# This is for the pyaff python module
pyexec_LTLIBRARIES 	= pyaff.la

pyaff_la_SOURCES	= pyaff.c
pyaff_la_LIBADD		= ../lib/libafflib.la
pyaff_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
pyaff_la_CFLAGS                = -fno-strict-aliasing
pyaff_la_LDFLAGS 	= -module -avoid-version $(PYTHON_LDFLAGS)
endif
