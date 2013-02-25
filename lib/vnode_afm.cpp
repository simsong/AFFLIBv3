/* vnode_afm: afm raw file implementation with optional metadata support
 * Distributed under the Berkeley 4-part license
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"
#include "vnode_afm.h"
#include "vnode_aff.h"
#include "vnode_split_raw.h"

/*
 * Notes on implementation:
 * AF_PAGES_PER_IMAGE_FILE is a segment read as a 64-bit number.
 * If its value is 0, then do not split the files.
 */

struct afm_private {
    AFFILE *aff;			// the AFFILE we use for the actual metadata
    AFFILE *sr;				// the AFFILE we use for the splitraw
    int sr_initialized;			// has the split-raw been setup from AFM?
};


static inline struct afm_private *AFM_PRIVATE(AFFILE *af)
{
    assert(af->v == &vnode_afm);
    return (struct afm_private *)(af->vnodeprivate);
}

/* Return 1 if a file has the AFF header or if the file doesn't
 * exist and its extension is .afm
 */
static int afm_identify_file(const char *filename,int exists)
{
    if(exists && access(filename,R_OK)!=0) return 0;	// needs to exist and it doesn't
    return af_ext_is(filename,"afm");
}


static int afm_close(AFFILE *af)
{
    struct afm_private *ap = AFM_PRIVATE(af);
    if(ap){
	if(ap->sr)  af_close(ap->sr);		// close the split files
	if(ap->aff) af_close(ap->aff);		// and close the AFF file
	memset(ap,0,sizeof(*ap));
	free(ap);
    }
    return 0;
}


static int invalid_extension_char(const char *extension,int ext_len)
{
    for(int i=0;i<ext_len;i++){
	if(extension[1]=='\000') return 1;
	if(extension[1]=='.') return 1;
	if(extension[1]=='/') return 1;
    }
    return 0;
}


static int afm_create(AFFILE *af)
{
    if (af_update_seg (af, AF_RAW_IMAGE_FILE_EXTENSION, 0, (const u_char *)SPLITRAW_DEFAULT_EXTENSION,
		       strlen(SPLITRAW_DEFAULT_EXTENSION))) {
	(*af->error_reporter)("split_raw_read_write_setup: %s: failed to write %s\n",
			      af->fname, AF_RAW_IMAGE_FILE_EXTENSION);
	afm_close(af);		// close the sub-file
	return -1;			// we failed
    }
    af_set_pagesize(af,AFM_DEFAULT_PAGESIZE);
    af_update_seg(af,AF_AFF_FILE_TYPE,0,(const u_char *)"AFM",3);
    return 0;
}

/*
 * The AFM is actually a shell that opens two
 * sub-implementations in their own files: an AFF file
 * and a split_raw file.
 */

static int afm_open(AFFILE *af)
{
    af->vnodeprivate = (void *)calloc(sizeof(struct afm_private),1);
    struct afm_private *ap = AFM_PRIVATE(af);
    ap->aff = af_open_with(af_filename(af),af->openflags,af->openmode,&vnode_aff);

    if(ap->aff==0){			// open failed?
	afm_close(af);
	return -1;
    }
    ap->aff->parent = af;

    /* If this is a new file, write out the default split raw extension */
    if(af->exists == 0){
	if(afm_create(af)) return -1;
    }

    /* If this is an old file, read the image_pagesize */
    if(af->exists){
	af->image_pagesize = ap->aff->image_pagesize;
    }

    /* Read the split raw extension */
    char raw_file_extension[4];
    size_t  len=3;				// don't overwrite the NUL

    memset(raw_file_extension,0,sizeof(raw_file_extension));
    if (af_get_seg(ap->aff,AF_RAW_IMAGE_FILE_EXTENSION,0,(unsigned char *)raw_file_extension,&len)) {
	(*af->error_reporter)("afm_open: %s: %s segment missing or too large\n",
			      af_filename(af),AF_RAW_IMAGE_FILE_EXTENSION);
	afm_close(af);
	return -1;
    }
    if(invalid_extension_char(raw_file_extension,len)){
	(*af->error_reporter)("afm_open: file extension contains invalid character\n",
		 af->fname, AF_RAW_IMAGE_FILE_EXTENSION);
	afm_close(af);
	return -1;
    }

    /* Now open the splitraw file */
    char *sr_filename = strdup(af_filename(af));
    char *ext = strrchr(sr_filename,'.');
    if(!ext){
	(*af->error_reporter)("afm_open: cannot find extension in '%s'",sr_filename);
	free(sr_filename);
	afm_close(af);
	return -1;
    }
    ext++;				// skip past '.'
    if(strlen(ext) != strlen(raw_file_extension)){
	(*af->error_reporter)("afm_open: file extension in '%s' too short",sr_filename);
	free(sr_filename);
	afm_close(af);
	return -1;
    }

    strcpy(ext,raw_file_extension);
    ap->sr  = af_open_with(sr_filename,af->openflags,af->openmode,&vnode_split_raw);
    if(ap->sr==0){
	(*af->error_reporter)("afm_open: could not open '%s'",sr_filename);
	free(sr_filename);
	afm_close(af);
	return -1;
    }
    ap->sr->parent = af;
    free(sr_filename);

    /* Additional setup will happen first time a data read/write call is made
     * by the function afm_read_write_setup().
     * This allows a new file to be created with af_open() and then to have
     * the parameters set with af_update_seg() calls, yet the split_raw
     * implementation gets the proper settings
     */
    return 0;
}



/*  afm_split_raw_setup:
 * Sets up the parameters of the split-raw by reading from the metadata file.
 * The advantage of doing it this way is that a new file can be opened,
 * the metadata parmeters set, and then an af_write() call made, and the values.
 * get copied.
 */
static int afm_split_raw_setup(AFFILE *af)
{
    struct afm_private *ap = AFM_PRIVATE(af);
    if(ap->sr_initialized) return 0;		// already setup

    /* The size of AF_PAGES_PER_RAW_IMAGE_FILE indicates whether the file is split.
     * If it is not present, or if it is 0-length, assume that the file is not split.
     */
    uint64_t pages_per_file = 0;
    size_t len = 0;
    if (af_get_seg(ap->aff,AF_PAGES_PER_RAW_IMAGE_FILE,0,0,&len)) {

	/* Not in file; put it there based on maxsize and image_pagesize,
	 * both of which better be set at this point
	 */
	if (af->image_pagesize < 1) {
	    (*af->error_reporter)("afm_split_raw_setup: image_pagesize==0\n");
	    return -1;
	}
	if (af->maxsize % af->image_pagesize) {
	    (*af->error_reporter)("afm_split_raw_setup: maxsize (%"I64d") "
				  "not a multiple of image_pagesize (%d)\n",
				  af->maxsize,af->image_pagesize);
	    return -1;
	}
	pages_per_file = af->maxsize / af->image_pagesize;
	if (af_update_segq (af, AF_PAGES_PER_RAW_IMAGE_FILE, pages_per_file)) {
	    (*af->error_reporter)("split_raw_read_write_setup: %s: failed to write %s\n",
				  af_filename(af), AF_PAGES_PER_RAW_IMAGE_FILE);
	    return -1;
	}
    }

    /* Now, read the segment (which might have just been put there) and set up the split_raw file */
    if(af_get_segq(af,AF_PAGES_PER_RAW_IMAGE_FILE,(int64_t *)&pages_per_file)){
	(*af->error_reporter)("split_raw_read_write_setup: %s: failed to write %s\n",
			      af_filename(af), AF_PAGES_PER_RAW_IMAGE_FILE);
	return -1;
    }

    /* Verify that splitraw's notion of the rawfilesize is the same as the
     * metadata's notion if the AFF image_size has been set
     */
    if (ap->aff->image_size && ap->aff->image_size != ap->sr->image_size) {
	(*af->error_reporter)("afm_split_raw_setup: internal error. "
			      "AFF image_size %"I64d" != SR image_size %"I64d"\n",
			      ap->aff->image_size,ap->sr->image_size);
	return -1;
    }

    /* Uses pages_per_file to set the maxsize of the split_raw if it hasn't been set yet*/
    if(ap->sr->maxsize==0){
	ap->sr->maxsize = pages_per_file * af->image_pagesize;
    }

    /* Verify that the parameters make sense */
    if (ap->sr->maxsize != (pages_per_file * af->image_pagesize) && pages_per_file>0) {
	(*af->error_reporter)("afm_split_raw_setup: %s: per size indicated by metadata (%d * %d) "
			      "doesn't match maxsize (%"I64d")\n",
			      af_filename(af),pages_per_file,af->image_pagesize,ap->sr->maxsize);
	return -1;
    }

    /* Push down the image_pagesize from the AFM to the split_raw */
    uint32_t image_pagesize = af->image_pagesize; // default to what's in memory
    af_get_seg(af,AF_PAGESIZE,&image_pagesize,0,0); // get from the AFF file if possible
    ap->sr->image_pagesize = af->image_pagesize; // overwrite the default with what the AFM file

    ap->sr_initialized = 1;
    return 0;
}

/*
 * the stat of the afm is the stat of the metafile,
 * but we don't do compression.
 */
static int afm_raw_vstat(AFFILE *af,struct af_vnode_info *vni)
{
    memset(vni,0,sizeof(*vni));		// clear it
    struct afm_private *ap = AFM_PRIVATE(af);
    af_vstat(ap->aff,vni);
    vni->supports_compression = 0;
    vni->supports_metadata    = 1;
    return 0;
}


/*
 * afm_get_seg:
 * If it is a page segment, satisfy it from the splitraw,
 * otherwise from the aff file.
 */
static int afm_get_seg(AFFILE *af,const char *name,uint32_t *arg,unsigned char *data,size_t *datalen)
{
    struct afm_private *ap = AFM_PRIVATE(af);
    int64_t page_num = af_segname_page_number(name);
    if(page_num>=0) return af_get_seg(ap->sr,name,arg,data,datalen);
    return af_get_seg(ap->aff,name,arg,data,datalen);

}


/*
 * afm_del_seg:
 * If it is a page segment, generate an error.
 * otherwise from the aff file.
 */
static int afm_del_seg(AFFILE *af,const char *segname)
{
    struct afm_private *ap = AFM_PRIVATE(af);
    int64_t page_num = af_segname_page_number(segname);
    if(page_num>=0){
	errno = ENOTSUP;
	return -1;
    }
    return af_del_seg(ap->aff,segname);
}


/*
 * afm_get_next_seg:
 * Try get_next_seg on the AFF file first until it has none left.
 * Then call get_next_seg of the splitraw until it has noneleft.
 */

static int afm_get_next_seg(AFFILE *af,char *segname,size_t segname_len,uint32_t *arg,
			    unsigned char *data,size_t *datalen_)
{
    struct afm_private *ap = AFM_PRIVATE(af);
    int r = af_get_next_seg(ap->aff,segname,segname_len,arg,data,datalen_);
    if(r==-1) return af_get_next_seg(ap->sr,segname,segname_len,arg,data,datalen_);
    return r;
}

/* afm_rewind_seg:
 * Rewind both the AFF file and the split_raw file(s)
 */
static int afm_rewind_seg(AFFILE *af)
{
    struct afm_private *ap = AFM_PRIVATE(af);
    if ( af_rewind_seg(ap->aff) ) return -1; // that's bad
    return af_rewind_seg(ap->sr);	// and rewind the splitraw
}


/* For afm_update_seg, hand off page updates to the split_raw implementation
 * and metadata updates to the AFF implementation.
 */
static int afm_update_seg(AFFILE *af, const char *name,
			  uint32_t arg,const u_char *value,uint32_t vallen)

{
    struct afm_private *ap = AFM_PRIVATE(af);
    int64_t page_num = af_segname_page_number(name); // <0 means update metadata
    if(page_num<0){
	return af_update_seg(ap->aff,name,arg,value,vallen);
    }
    return af_update_seg(ap->sr,name,arg,value,vallen);
}


static int afm_read(AFFILE *af, unsigned char *buf, uint64_t pos,size_t count)
{
    struct afm_private *ap = AFM_PRIVATE(af);
    if(ap->sr_initialized==0 && afm_split_raw_setup(af)) return -1;
    return (*ap->sr->v->read)(ap->sr,buf,pos,count);
}

static int afm_write(AFFILE *af, unsigned char *buf, uint64_t pos,size_t count)
{
    struct afm_private *ap = AFM_PRIVATE(af);
    if(ap->sr_initialized==0 && afm_split_raw_setup(af)) return -1;
    af_set_callback(ap->sr,af->w_callback);               // update the callback
    int r = (*ap->sr->v->write)(ap->sr,buf,pos,count);  // call split_raw's write
    if(ap->sr->image_size > af->image_size){
	af->image_size      = ap->sr->image_size; // image was extended; note this in parent & AFF file
	ap->aff->image_size = ap->sr->image_size; // copy over the image size
    }
    return r;
}


struct af_vnode vnode_afm = {
    AF_IDENTIFY_AFM,
    AF_VNODE_TYPE_COMPOUND|AF_VNODE_TYPE_RELIABLE|AF_VNODE_MAXSIZE_MULTIPLE|AF_VNODE_NO_SEALING,
    "AFM (AFF metadata with split raw file)",
    afm_identify_file,
    afm_open,
    afm_close,
    afm_raw_vstat,			// nothing aff specific here.
    afm_get_seg,			// get seg
    afm_get_next_seg,			// get_next_seg
    afm_rewind_seg,			// rewind_seg
    afm_update_seg,			// update_seg
    afm_del_seg,			// del_seg (afm_open fills in aff_del_seg)
    afm_read,				// read
    afm_write				// write
};

