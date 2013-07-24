# Distributed under the Berekeley 4-part license

SUBDIRS = lib tools lzma443 tests doc pyaff man

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = afflib.pc

include_HEADERS = 
pkginclude_HEADERS = lib/afflib.h lib/afflib_i.h lib/aftimer.h lib/utils.h  

ACLOCAL_AMFLAGS = -I m4

RELEASE_USER = simsong@
RELEASE_HOST = www.afflib.org
RELEASE_DIR  = afflib.org/

RELEASE_LOC  = $(RELEASE_DIR)/downloads/
CHANGES_LOC  = $(RELEASE_DIR)/ChangeLog.txt
RELEASE_FN   = $(PACKAGE)_version.txt
RELEASE_PATH = $(RELEASE_LOC)/$(RELEASE_FN)
RELEASE_SSH  = $(RELEASE_USER)$(RELEASE_HOST):$(RELEASE_LOC)
RELEASE	     = $(PACKAGE)-$(VERSION)

AM_CFLAGS = -Wall
AM_CPPFLAGS = -Wall


release:
	make prerelease
	make distcheck
	make the_release

prerelease:
	@echo Making sure SVN is up to date
	svn update
	@echo update PACKAGE_VERSION in win32 directory
	sed s/PACKAGE_VERSION.\*/PACKAGE_VERSION\ \"$(PACKAGE_VERSION)\"/ win32/affconfig.h > win32/affconfig.h.$$
	mv -f win32/affconfig.h.$$ win32/affconfig.h
	@echo Commit back changes
	svn commit -m 'make prerelease'
	@echo Building and uploading the release...
	@echo Making release $(RELEASE)
	@echo
	echo
	wget http://$(RELEASE_HOST)/downloads/$(RELEASE_FN)
	@echo Version `cat $(RELEASE_FN)` is on the server.
	python checkversion.py $(RELEASE_FN) $(RELEASE)
	/bin/rm $(RELEASE_FN)

getrelease:
	@echo testing release on your system
	wget http://$(PACKAGE).tar.gz
	tar xfz $(PACKAGE).tar.gz
	(cd afflib-*;./configure;make;make test_crypto)

the_release: $(RELEASE).tar.gz
	gpg --detach-sign $(RELEASE).tar.gz

DOCS = BUGLIST.txt README_Linux.txt README_Win32.txt \
	doc/crypto_doc.txt \
	doc/crypto_design.txt \
	doc/announce_1.7.txt \
	doc/announce_1.8.txt \
	doc/announce_2.2.txt

EXTRA_DIST = $(DOCS) \
	bootstrap.sh \
	make_mingw.sh \
	m4/acx_pthread.m4 \
	afflib.spec.in \
	afflib.spec \
	afflib.pc.in \
	afflib.pubkey.asc \
	tests/encrypted.raw \
	tests/encrypted.aff \
	win32/Changes.txt \
	win32/README_MSVC++.txt \
	win32/affconfig.h \
	win32/afflib.mak \
	win32/make.bat


#
# Note: don't forget to run autoreconf when significant changes are made
#
