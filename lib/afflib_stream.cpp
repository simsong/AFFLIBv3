/*
 * The AFFLIB data stream interface.
 * Supports the page->segment name translation, and the actual file pointer.
 * Distributed under the Berkeley 4-part license.
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"


/****************************************************************
 *** Internal Functions.
 ****************************************************************/

#ifdef _WIN32
#define ASIZE SSIZE_T
#else
#define ASIZE ssize_t
#endif


/*
 * af_set_maxsize
 * Sets the maxsize.
 Fails with -1 if imagesize >= 0 unless this is a raw or split_raw file
 */
int af_set_maxsize(AFFILE *af,int64_t maxsize)
{
    AF_WRLOCK(af);
    if(af->image_size>0){
	(*af->error_reporter)("Cannot set maxsize as imagesize is already set (%"I64d")",af->image_size);
	AF_UNLOCK(af);
	return -1;	// now allowed to set if imagesize is bigger than 0
    }
    if((af->image_pagesize!=0)
       && (af->v->type & AF_VNODE_MAXSIZE_MULTIPLE)
       && (maxsize % af->image_pagesize != 0)){
	(*af->error_reporter)("Cannot set maxsize to %"I64d" --- not multiple of pagesize=%d\n",
			      maxsize,af->image_pagesize);
	AF_UNLOCK(af);
	return -1;
    }
    af->maxsize = maxsize;
    AF_UNLOCK(af);
    return 0;
}

const unsigned char *af_badflag(AFFILE *af)
{
    return af->badflag;
}


/****************************************************************
 *** Stream-level interface
 ****************************************************************/

static int af_get_pagebuf(AFFILE *af, int64_t pagenum)
{
    if(!af->pb || af->pb->pagenum != pagenum)
    {
	af->pb = af_cache_alloc(af, pagenum);
	if(!af->pb)
	    return -1;
    }

    if(!af->pb->pagebuf_valid)
    {
	size_t pagebytes = af->image_pagesize;
	if(af_get_page(af, pagenum, af->pb->pagebuf, &pagebytes) < 0)
	    return -1;

	af->pb->pagebuf_valid = 1;
	af->pb->pagebuf_bytes = pagebytes;
    }

    return 0;
}

extern "C" ASIZE af_read(AFFILE *af,unsigned char *buf,ASIZE count)
{
    int total = 0;

    AF_WRLOCK(af);			// wrlock because cache may change
    if (af_trace) fprintf(af_trace,"af_read(%p,%p,%d) (pos=%"I64d")\n",af,buf,(int)count,af->pos);
    if (af->v->read){			// check for bypass
	int r = (af->v->read)(af, buf, af->pos, count);
	if(r>0) af->pos += r;
	AF_UNLOCK(af);
	return r;
    }

    /* performance improvement: use af->image_size if it is set */
    uint64_t offset = af->pos;		/* where to start */

    if(af->image_size==0) {goto done;}		// no data in file
    if(af->pos > af->image_size) {goto done;}	// seeked beyond end of file
    if(af->pos+count > af->image_size) count = af->image_size - af->pos; // only this much left in file


    /* Make sure we have a pagebuf if none was defined */
    if(af->image_pagesize==0){		// page size not defined
	errno = EFAULT;
	total=-1;
	goto done;
    }

    while(count>0){
	int64_t new_page = offset / af->image_pagesize;

	if(af_get_pagebuf(af, new_page) < 0)
	{
	    /* if nothing was read yet, return 0 for EOF or -1 for read error */
	    /* ENOENT (page not found) means EOF, other errno means read error */
	    if(!total && errno != ENOENT)
		total = -1;
	    break;
	}

	// Compute how many bytes can be copied...
	// where we were reading from
	u_int page_offset   = (u_int)(offset - af->pb->pagenum * af->image_pagesize);

	if(page_offset > af->pb->pagebuf_bytes){
	    /* Page is short. */
	    /* Question - should we advance af->pos to the next page? */
	    break;
	}

	u_int page_left     = af->pb->pagebuf_bytes - page_offset; // number we can get out
	u_int bytes_to_read = count;

	if(bytes_to_read > page_left)               bytes_to_read = page_left;
	if(bytes_to_read > af->image_size - offset) bytes_to_read = (u_int)(af->image_size - offset);

	if(bytes_to_read==0) break; // that's all we could get

	/* Copy out the bytes for the user */
	memcpy(buf,af->pb->pagebuf+page_offset,bytes_to_read); // copy out
	af->bytes_memcpy += bytes_to_read;
	buf     += bytes_to_read;
	offset  += bytes_to_read;
	count   -= bytes_to_read;
	total   += bytes_to_read;
	af->pos += bytes_to_read;
    }
    /* We have copied all of the user's requested data, so return */
 done:
    AF_UNLOCK(af);
    return total;
}


/*
 * Handle writing to the file...
 * af_write() --- returns the number of bytes written
 *
 */

int af_write(AFFILE *af,unsigned char *buf,size_t count)
{
    AF_WRLOCK(af);
    if (af_trace){
	fprintf(af_trace,"af_write(af=%p,buf=%p,count=%d) pos=%"I64d"\n", af,buf,(int)count,af->pos);
    }
    /* Invalidate caches */
    af_invalidate_vni_cache(af);

    /* vnode write bypass:
     * If a write function is defined, use it and avoid the page and cache business.
     */
    if (af->v->write){
	int r = (af->v->write)(af, buf, af->pos, count);
	if(r>0){
	    af->pos += r;
	    af->bytes_written += r;
	}
	if(af->pos >= af->image_size) af->image_size = af->pos;
	AF_UNLOCK(af);
	return r;
    }

    /* If no pagesize has been set, go with the default pagesize */
    if(af->image_pagesize==0){
	if(af_set_pagesize(af,AFF_DEFAULT_PAGESIZE)){
	    AF_UNLOCK(af);
	    return -1;
	}
    }

    int64_t offset = af->pos;		// where to start

    /* If the correct segment is not loaded, purge the current segment */
    int64_t write_page = offset / af->image_pagesize;
    if(af->pb && af->pb->pagenum!=write_page){
	af_cache_flush(af);
	af->pb = 0;
    }

    int write_page_offset = (int)(offset % af->image_pagesize);

    /* Page Write Bypass:
     * If no data has been written into the current page buffer,
     * and if the position of the stream is byte-aligned on the page buffer,
     * and if an entire page is being written,
     * just write it out and update the pointers, then return.
     */
    if(!af->pb && !write_page_offset && !(count % af->image_pagesize))
    {
	for(size_t written = 0; written < count; written += af->image_pagesize)
	{
	    // copy into cache if we have this page anywhere in our cache
	    af_cache_writethrough(af, write_page, buf + written, af->image_pagesize);

	    if(af_update_page(af, write_page, buf + written, af->image_pagesize) < 0)
	    {
		AF_UNLOCK(af);
		return -1;
	    }

	    af->pos += af->image_pagesize;
	    if(af->pos > af->image_size)
		af->image_size = af->pos;

	    write_page++;
	}

	AF_UNLOCK(af);
	return count;
    }

    /* Can't use high-speed optimization; write through the cache */
    int total = 0;
    while(count>0){
	/* If no page is loaded, or the wrong page is loaded, load the correct page */
	int64_t pagenum = offset / af->image_pagesize;	// will be the segment we want
	if(af->pb==0 || af->pb->pagenum != pagenum){
	    af->pb = af_cache_alloc(af,pagenum);
	    af->pb->pagebuf_bytes = af->image_pagesize;
	    assert(af->pb->pagenum == pagenum);

	    /* Now try to load the page.
	     * If we can't load it, then we are creating a new page.
	     */
	    if(af_get_page(af,af->pb->pagenum,af->pb->pagebuf, &af->pb->pagebuf_bytes)){
		/* Creating a new page; note that we have no bytes in this page */
		af->pb->pagebuf_bytes = 0;
	    }
	}
	// where writing to
	u_int seg_offset = (u_int)(offset - af->pb->pagenum * af->image_pagesize);

	// number we can write into
	u_int seg_left   = af->image_pagesize - seg_offset;
	u_int bytes_to_write = count;

	if(bytes_to_write > seg_left) bytes_to_write = seg_left;

	if(bytes_to_write==0) break; // that's all we could get

	/* Copy out the bytes for the user */
	memcpy(af->pb->pagebuf+seg_offset,buf,bytes_to_write); // copy into the page cache
	af->bytes_memcpy += bytes_to_write;

	if(af->pb->pagebuf_bytes < seg_offset+bytes_to_write){
	    af->pb->pagebuf_bytes = seg_offset+bytes_to_write; // it has been extended.
	}

	buf     += bytes_to_write;
	offset  += bytes_to_write;
	count   -= bytes_to_write;
	total   += bytes_to_write;
	af->pos += bytes_to_write;
	af->pb->pagebuf_valid = 1;
	af->pb->pagebuf_dirty = 1;

	/* If we wrote out all of the bytes that were left in the segment,
	 * then we are at the end of the segment, write it back...
	 */
	if(seg_left == bytes_to_write){
	    if(af_cache_flush(af)){
		AF_UNLOCK(af);
		return -1;
	    }
	}

	/* If we have written more than the image size, update the image size */
	if((uint64_t)offset > af->image_size) af->image_size = offset;
    }
    /* We have copied all of the user's requested data, so return */
    AF_UNLOCK(af);
    return total;
}

/* No lock needed? */
int af_is_badsector(AFFILE *af,const unsigned char *buf)
{
    if(af->badflag_set==0) return 0;
    if(af->badflag==0) return 0;
    return memcmp(af->badflag,buf,af->image_sectorsize)==0;
}
