/*
 * afflib_os.cpp:
 *
 * The OS-specific features of AFFLIB
 *
 * This file is a work of a US government employee and as such is in the Public domain.
 * Simson L. Garfinkel, March 12, 2012
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version<500000
#undef HAVE_SYS_DISK_H
#endif

#if defined(HAVE_SYS_DISK_H)
#include <sys/disk.h>
#endif

#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>			// needed for Linux
#endif

/****************************************************************
 *** Extra code for Windows...
 ****************************************************************/

/* No longer needed with VC2008 */
#if 0
#if defined(WIN32) and !defined(__MINGW_H)
#pragma warning(disable: 4996)
int64 ftello(FILE *stream)
{
    fpos_t pos;
    if(fgetpos(stream,&pos) != 0){
	return -1;
    }
    return pos;
}

int fseeko(FILE *stream,int64 offset,int whence)
{
    switch(whence){
    case SEEK_SET:
	break;				// jump down to fsetpos()
    case SEEK_CUR:
	offset += ftello(stream);
	break;
    case SEEK_END:
	fseek(stream,0L,SEEK_END);	// go to the end; hope this works for big files
	offset = ftello(stream) - offset;
	break;
    default:
	return -1;
    }
    return fsetpos(stream,&offset);
}
#endif
#endif




/****************************************************************/


/* af_figure_media():
 *
 * This is a function that returns, for the file handle of an open
 * device, the sector_size, total_sectors, and maximum number of
 * blocks that can be read at a time (or 0 if there is no max).  There
 * is a generic implementation at the bottom, and operating-specific
 * versions above.
 */


int	af_figure_media(int fd,struct af_figure_media_buf *afb)
{
    memset(afb,0,sizeof(*afb));
    afb->version = 1;

#ifdef __APPLE__
#define MEDIA_FIGURED
    if(ioctl(fd,DKIOCGETBLOCKSIZE,&afb->sector_size)){
	afb->sector_size = 512;		// assume 512
    }
    if(ioctl(fd,DKIOCGETBLOCKCOUNT,&afb->total_sectors)){
	afb->total_sectors=0;		// seeking not allowed on stdin
    }
    if(ioctl(fd,DKIOCGETMAXBLOCKCOUNTREAD,&afb->max_read_blocks)){
	afb->max_read_blocks = 0;	// read all you want
    }
#endif
#if defined(__FreeBSD__) && defined(DIOCGSECTORSIZE)
#define MEDIA_FIGURED
    if(ioctl(fd,DIOCGSECTORSIZE,&afb->sector_size)){
	afb->sector_size = 512;		// can't figure it out; go with the default
    }
    off_t inbytes=0;
    if(ioctl(fd,DIOCGMEDIASIZE,&inbytes)){
	afb->total_sectors = 0;
    }
    if(inbytes % afb->sector_size != 0){
	fprintf(stderr,"ioctl(DIOCGSECTORSIZE) returns %d bytes\n", afb->sector_size);
	fprintf(stderr,"ioctl(DIOCGMEDIASIZE) returns %d bytes\n", inbytes);
	fprintf(stderr,"which is not an even number of sectors.\n");
	return -1;
    }
    afb->total_sectors = inbytes / afb->sector_size;
    afb->max_read_blocks = 0;
#endif
#ifdef linux
#define MEDIA_FIGURED
    /* With Linux, we figure out how many bytes there are and get sector size
     * from a #define
     */

    afb->sector_size = BLOCK_SIZE;
#ifdef BLKGETSIZE64
    uint64_t total_bytes=0;
    if(ioctl(fd,BLKGETSIZE64,&total_bytes)){
	total_bytes = 0;
    }
#else
    int total_bytes=0;
    if(ioctl(fd,BLKGETSIZE,&total_bytes)){
	total_bytes = 0;
    }
#endif


    afb->total_sectors = total_bytes / afb->sector_size;
    afb->max_read_blocks = 0;
#endif
#ifndef MEDIA_FIGURED

    /* Unknown OS type. Try our best-effort guess,
     */
#ifdef BLOCK_SIZE
    afb->sector_size = BLOCK_SIZE;	// it's a good guess
#else
    afb->sector_size = 512;	// it's a good guess
#endif

    /* Try seeking to the end of fd and ask where we are! */

    off_t start_pos   = lseek(fd,0,SEEK_CUR); // find where we are
    off_t end_of_file = lseek(fd,0,SEEK_END);

    if(end_of_file==-1){
	end_of_file = 0;		// can't figure it.
    }
    lseek(fd,start_pos,SEEK_SET);	// go back to the starting position

    afb->total_sectors = end_of_file / afb->sector_size;
    afb->max_read_blocks = 0;
#endif
    return 0;
}



