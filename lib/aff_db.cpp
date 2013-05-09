/* Distributed under the 4-part Berkeley License */

/*
 * afflib_db.cpp:
 *
 * Functions for the manipulation of the AFF database.
 */


#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"
#include "aff_db.h"


/****************************************************************
 *** Low-level functions
 ****************************************************************/

/****************************************************************
 *** Probe Functions
 ****************************************************************/

int af_probe_next_seg(AFFILE *af,
		       char *segname,
		       size_t segname_len,
		       uint32_t *arg_, // optional arg
		       size_t *datasize_, // optional get datasize
		       size_t *segsize_, // optional get size of entire segment
		       int do_rewind) // optional rewind af->aseg, otherwise leave at start of segment data
{
    if(!af->aseg)(*af->error_reporter)("af_probe_next_segment only works with aff files");

    struct af_segment_head segh;
    memset(&segh,0,sizeof(segh));

    uint64_t start = ftello(af->aseg);
#ifdef __BORLANDC__
    fseeko(af->aseg, start, SEEK_SET) ;    // Windows is dumb :-(
#endif

    if(fread(&segh,sizeof(segh),1,af->aseg)!=1){
	return AF_ERROR_EOF;
    }
    if(strcmp(segh.magic,AF_SEGHEAD)!=0){
	snprintf(af->error_str,sizeof(af->error_str),"afflib: segh is corrupt at %" PRIu64,start);
	return AF_ERROR_SEGH;
    }

    uint32_t name_len = ntohl(segh.name_len);
    uint32_t datasize = ntohl(segh.data_len);
    if(name_len>AF_MAX_NAME_LEN){
	snprintf(af->error_str,sizeof(af->error_str),"afflib: name_len=%"PRIu32" (an outrageous value)",name_len);
	return AF_ERROR_NAME;
    }

    if(name_len+1 > segname_len){
	fseeko(af->aseg,start,SEEK_SET); // rewind to start
	return -2;
    }

    if(fread(segname,1,name_len,af->aseg)!=name_len){
	fseeko(af->aseg,start,SEEK_SET); // rewind
	return -1;
    }
    segname[name_len] = 0;

    if(do_rewind) fseeko(af->aseg,start,SEEK_SET); // rewind

    uint32_t segsize = sizeof(struct af_segment_head)
	+ sizeof(struct af_segment_tail)
	+ name_len + datasize;

    if(arg_)      *arg_      = ntohl(segh.flag);
    if(datasize_) *datasize_ = datasize;
    if(segsize_)  *segsize_ = segsize;

#ifdef DEBUG
    fprintf(stderr,"af_probe_next_seg(segname=%s datasize=%d segsize=%d) do_rewind=%d\n",
	    segname,datasize,segsize,do_rewind);
#endif
    return 0;
}

/* af_backspace:
 * moves back one segment in the aff file.
 * Returns 0 if success, -1 if we can't back up further.
 */
int af_backspace(AFFILE *af)
{
    struct af_segment_tail segt;

    uint64_t start = ftello(af->aseg);

    if(start==sizeof(AF_HEADER) || start<sizeof(segt)) return -1; // can't backspace further

    uint64_t pos_tail = start - sizeof(segt); // backspace to read the tail
    fseeko(af->aseg,pos_tail,SEEK_SET);
    if(fread(&segt,sizeof(segt),1,af->aseg)!=1){
	fseeko(af->aseg,start,SEEK_SET); // put it back
	return -1;			// can't read segt?
    }
    /* Verify that this is a segment tail. if it isn't, put the file pointer back and return */
    if(memcmp(segt.magic,AF_SEGTAIL,sizeof(AF_SEGTAIL))!=0){
	fseeko(af->aseg,start,SEEK_SET);
	return -1;
    }

    /* Now I know how long the segment was. Compute where it started */
    uint64_t seg_start = start - ntohl(segt.segment_len);
    fseeko(af->aseg,seg_start,SEEK_SET);
    return 0;
}



/* find the given segment and return 0 if found.
 * Leave the file pointer positioned at the start of the segment.
 * Return -1 if segment is not found, and leave pointer at the end
 */
int	aff_find_seg(AFFILE *af,const char *segname,
		    uint32_t *arg,
		    size_t *datasize,
		    size_t *segsize)
{
    char   next_segment_name[AF_MAX_NAME_LEN];
    size_t next_segsize = 0;
    size_t next_datasize = 0;
    uint32_t next_arg;

    /* Try to use the TOC to find the segment in question */
    struct aff_toc_mem *adm = aff_toc(af,segname);
    if(adm){
	if(datasize==0 && segsize==0 && arg==0){
	    /* User was just probing to see if it was present. And it is! */
	    return 0;
	}
	fseeko(af->aseg,adm->offset,SEEK_SET);
    }
    else {
	af_rewind_seg(af);
    }
    while(af_probe_next_seg(af,next_segment_name,sizeof(next_segment_name),
			    &next_arg,&next_datasize,&next_segsize,1)==0){
	if(strcmp(next_segment_name,segname)==0){	// found the segment!
	    if(datasize) *datasize = next_datasize;
	    if(segsize)  *segsize  = next_segsize;
	    if(arg)      *arg      = next_arg;
	    return 0;			// return the info
	}
	fseeko(af->aseg,next_segsize,SEEK_CUR);	// skip the segment
    }
    return -1;				// couldn't find segment
}

int af_get_segq(AFFILE *af,const char *name,int64_t *aff_quad)
{
    unsigned char buf[8];
    size_t  bufsize = sizeof(buf);

    if(af_get_seg(af,name,0,(unsigned char *)&buf,&bufsize)){
	return -1;			// couldn't get it...
    }
    if(bufsize!=sizeof(struct aff_quad)){		// make sure size is good.
	return -1;
    }

    *aff_quad = af_decode_q(buf);
    return 0;
}


/* af_update_segq:
 * Update the named aff_quad-byte value.
 */


int af_update_segq(AFFILE *af, const char *name, int64_t value)
{
    struct aff_quad  q;
    q.low  = htonl((uint32_t)(value & 0xffffffff));
    q.high = htonl((uint32_t)(value >> 32));
    return af_update_seg(af,name,AF_SEG_QUADWORD,(const u_char *)&q,8);
}


