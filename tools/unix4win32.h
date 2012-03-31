/*
 * This file is a work of a US government employee and as such is in the Public domain.
 * Simson L. Garfinkel, March 12, 2012
 */

#ifdef WIN32
#include "getopt.h"			// will pull from win32 directory
#include <malloc.h>
#include <windows.h>
#include <io.h>
#ifndef F_OK
#define F_OK 00
#endif

#ifndef R_OK
#define R_OK 04
#endif

#ifndef S_IFBLK
#define S_IFBLK -1			// will never be used
#endif

#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN
#endif
#endif


