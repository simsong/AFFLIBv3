/*
 * AFF/qemu glue
 *
 * 2008 by Simson L. Garfinkel
 *
 * This file is a work of a US government employee and as such is in the Public domain.
 * Simson L. Garfinkel, March 12, 2012
 *
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"

#ifdef USE_QEMU

extern "C" {
#include "qemu/qemu-common.h"
#include "qemu/block_int.h"
}


/* Return 1 if a file is a qemu file... */
static int vmdk_identify_file(const char *filename,int exists)
{
    return af_ext_is(filename,"vmdk");
}

/* Return 1 if a file is a qemu file... */
static int dmg_identify_file(const char *filename,int exists)
{
    return af_ext_is(filename,"dmg");
}

/* Return 1 if a file is a qemu file... */
static int sparseimage_identify_file(const char *filename,int exists)
{
    return af_ext_is(filename,"sparseimage");
}

#define QEMU_HANDLE(af) ((BlockDriverState *)af->vnodeprivate)

static int qemu_open(AFFILE *af)
{
    BlockDriverState *bs;
    BlockDriver *drv=NULL;
    uint64_t	total_sectors=0;
    static int bdrv_init_called  = 0;

    if(bdrv_init_called==0){		// DO NOT CALL MORE THAN ONCE
	bdrv_init();
	bdrv_init_called = 1;
    }
    bs = bdrv_new("");
    if (bs == NULL) return -1;
    if(bdrv_open2(bs,af_filename(af),0,drv)!=0){
	bdrv_delete(bs);
	return -1;
    }
    bdrv_get_geometry(bs, &total_sectors);

    af->image_pagesize   = 1024*1024*1;	// megabyte for now
    af->image_size = total_sectors * 512;

    af->vnodeprivate = (void *)bs;
    return 0;
}


static int qemu_vstat(AFFILE *af,struct af_vnode_info *vni)
{
    vni->imagesize = af->image_size;
    vni->pagesize = af->image_pagesize;
    vni->has_pages = 1;			// use the AFF page system
    return 0;
}

static int qemu_close(AFFILE *af)
{
    bdrv_delete(QEMU_HANDLE(af));
    return 0;
}


static int qemu_rewind_seg(AFFILE *af)
{
    af->cur_page = -1;			// starts at the metadata
    return 0;
}


static int qemu_get_seg(AFFILE *af,const char *name, uint32_t *arg,
		       unsigned char *data,size_t *datalen)
{
    /* Is the user asking for a page? */
    int64_t segnum = af_segname_page_number(name);
    if(segnum>=0){
	/* Get the segment number */
	if(data==0){
	    /* Need to make sure that the segment exists */
	    if(segnum * (af->image_pagesize+1) > (int64_t) af->image_size ){
		return -1; // this segment does not exist
	    }
	    if(datalen) *datalen =af->image_pagesize;	// just return the chunk size
	    return 0;
	}
	int64_t sector_start = segnum * af->image_pagesize / 512;
	u_int   sector_count = af->image_pagesize/512;
	if(datalen==0) return -1;
	if(sector_count*512 > *datalen) return -1; // no room
	return bdrv_read(QEMU_HANDLE(af),sector_start,data,sector_count);
    }

    /* See if it is a page name we understand */
    if(strcmp(name,AF_PAGESIZE)==0){
	if(arg) *arg = af->image_pagesize;
	return 0;
    }
    if(strcmp(name,AF_IMAGESIZE)==0){
	if(arg) *arg = 0;
	if(datalen==0) return 0;
	if(*datalen==0){
	    *datalen = 8;	// the structure is 8 bytes long
	    return 0;
	}
	if(*datalen<8) return -2;

	struct aff_quad  q;
	q.low  = htonl((uint32_t)(af->image_size & 0xffffffff));
	q.high = htonl((uint32_t)(af->image_size >> 32));
	memcpy(data,&q,8);
	return 0;
    }
    if(strcmp(name,AF_SECTORSIZE)==0){
	if(arg) *arg=512;		// seems to be what QEMU uses
	if(datalen) *datalen = 0;
	return 0;
    }
    if(strcmp(name,AF_DEVICE_SECTORS)==0){
	/* Is this in flag or a quad word? */
	if(arg) *arg = af->image_size / 512;
	if(datalen) *datalen = 0;
	return 0;
    }

    /* They are asking for a metdata segment. If we have wide character type
     * compiled in for libqemu, just ignore it, because afflib doesn't do wide characters
     * at the moment...
     */

    return -1;			// don't know this header
}

static const char *emap[] = {
    AF_PAGESIZE,
    AF_IMAGESIZE,
    AF_SECTORSIZE,
    AF_DEVICE_SECTORS,
    0
};


static int qemu_get_next_seg(AFFILE *af,char *segname,size_t segname_len,uint32_t *arg,
			unsigned char *data,size_t *datalen)
{
    /* Figure out what the next segment would be, then get it */
    /* Metadata first */
    if(af->cur_page<0){
	/* Find out how many mapped segments there are */
	int mapped=0;
	for(mapped=0;emap[mapped];mapped++){
	}
	if(-af->cur_page >= mapped ){
	    af->cur_page = 0;
	    goto get_next_data_seg;
	}
	int which = 0 - af->cur_page;	// which one to get
	af->cur_page--;			// go to the next one
	if(segname_len < strlen(emap[which])) return -2; // not enough room for segname
	strlcpy(segname,emap[which],segname_len);	// give caller the name of the mapped segment.
	return qemu_get_seg(af,segname,arg,data,datalen);
    }

 get_next_data_seg:
    if(af->cur_page * af->image_pagesize >= (int64_t)af->image_size) return -1; // end of list
    /* Make the segment name */
    char pagename[AF_MAX_NAME_LEN];		//
    memset(pagename,0,sizeof(pagename));
    snprintf(pagename,sizeof(pagename),AF_PAGE,af->cur_page++);

    int r = 0;
    /* Get the segment, if it is wanted */
    if(data) r = qemu_get_seg(af,pagename,arg,data,datalen);

    /* If r==0 and there is room for copying in the segment name, return it */
    if(r==0){
	if(strlen(pagename)+1 < segname_len){
	    strlcpy(segname,pagename,segname_len);
	    return 0;
	}
	/* segname wasn't big enough */
	return -2;
    }
    return r;			// some other error
}

struct af_vnode vnode_vmdk = {
    AF_IDENTIFY_VMDK,
    AF_VNODE_TYPE_PRIMITIVE|AF_VNODE_NO_SIGNING|AF_VNODE_NO_SEALING,
    "VMDK(LIBQEMU)",
    vmdk_identify_file,
    qemu_open,
    qemu_close,
    qemu_vstat,
    qemu_get_seg,			// get seg
    qemu_get_next_seg,			// get_next_seg
    qemu_rewind_seg,			// rewind_seg
    0,					// update_seg
    0,					// del_seg
    0,					// read
    0					// write
};


struct af_vnode vnode_dmg = {
    AF_IDENTIFY_DMG,
    AF_VNODE_TYPE_PRIMITIVE|AF_VNODE_NO_SIGNING|AF_VNODE_NO_SEALING,
    "DMG(LIBQEMU)",
    dmg_identify_file,
    qemu_open,
    qemu_close,
    qemu_vstat,
    qemu_get_seg,			// get seg
    qemu_get_next_seg,			// get_next_seg
    qemu_rewind_seg,			// rewind_seg
    0,					// update_seg
    0,					// del_seg
    0,					// read
    0					// write
};


struct af_vnode vnode_sparseimage = {
    AF_IDENTIFY_SPARSEIMAGE,
    AF_VNODE_TYPE_PRIMITIVE|AF_VNODE_NO_SIGNING|AF_VNODE_NO_SEALING,
    "SPARSEIMAGE(LIBQEMU)",
    sparseimage_identify_file,
    qemu_open,
    qemu_close,
    qemu_vstat,
    qemu_get_seg,			// get seg
    qemu_get_next_seg,			// get_next_seg
    qemu_rewind_seg,			// rewind_seg
    0,					// update_seg
    0,					// del_seg
    0,					// read
    0					// write
};


#endif
