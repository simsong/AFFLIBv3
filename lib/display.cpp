/*
 * A list of the segments that should be displayed as a quadword.
 * This file is a work of a US government employee and as such is in the Public domain.
 * Simson L. Garfinkel, March 12, 2012
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"

static const char *quads[] = {
    AF_IMAGESIZE,
    AF_BADSECTORS,
    AF_BLANKSECTORS,
    AF_DEVICE_SECTORS,
    0
};


int af_display_as_quad(const char *segname)
{
    for(int i=0;quads[i];i++){
	if(strcmp(segname,quads[i])==0) return true;
    }
    return false;
}

int af_display_as_hex(const char *segname)
{
    if(strcmp(segname,AF_MD5)==0) return 1;
    if(strcmp(segname,AF_SHA1)==0) return 1;
    if(strcmp(segname,AF_SHA256)==0) return 1;
    if(strcmp(segname,AF_IMAGE_GID)==0) return 1;
    return 0;
}

