/*
 * vnode_aff.cpp:
 *
 * Functions for the manipulation of AFF files...
 * Distributed under the Berkeley 4-part license
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"
#include "vnode_afd.h"
#include "aff_db.h"

#ifndef F_OK
#define F_OK 00
#endif

#ifndef R_OK
#define R_OK 04
#endif


#if defined(WIN32) and !defined(HAVE__MINGW_H)
/**********************************************************************
 * Implement dirent-style opendir/readdir/rewinddir/closedir on Win32
 *
 * Functions defined are opendir(), readdir(), rewinddir() and
 * closedir() with the same prototypes as the normal dirent.h
 * implementation.
 *
 * Does not implement telldir(), seekdir(), or scandir().  The dirent
 * struct is compatible with Unix, except that d_ino is always 1 and
 * d_off is made up as we go along.
 *
 * The DIR typedef is not compatible with Unix.
 **********************************************************************/

extern "C" DIR *opendir(const char *dir)
{
	DIR *dp;
	char *filespec;
	long handle;
	int index;

	filespec = (char *)malloc(strlen(dir) + 2 + 1);
	strcpy(filespec, dir);
	index = strlen(filespec) - 1;
	if (index >= 0 && (filespec[index] == '/' || (filespec[index] == '\\' )))
		filespec[index] = '\0';
	strcat(filespec, "\\*");

	dp = (DIR *) malloc(sizeof(DIR));
	dp->offset = 0;
	dp->finished = 0;

	if ((handle = _findfirst(filespec, &(dp->fileinfo))) < 0) {
		if (errno == ENOENT) {
			dp->finished = 1;
		} else {
			free(dp);
			free(filespec);
			return NULL;
		}
	}
	dp->dir = strdup(dir);
	dp->handle = handle;
	free(filespec);

	return dp;
}

extern "C" struct dirent *readdir(DIR *dp)
{
	if (!dp || dp->finished)
		return NULL;

	if (dp->offset != 0) {
		if (_findnext(dp->handle, &(dp->fileinfo)) < 0) {
			dp->finished = 1;
			return NULL;
		}
	}
	dp->offset++;

	strlcpy(dp->dent.d_name, dp->fileinfo.name, _MAX_FNAME+1);
	dp->dent.d_ino = 1;
	dp->dent.d_reclen = strlen(dp->dent.d_name);
	dp->dent.d_off = dp->offset;

	return &(dp->dent);
}

extern "C" int readdir_r(DIR *dp, struct dirent *entry, struct dirent **result)
{
	if (!dp || dp->finished) {
		*result = NULL;
		return 0;
	}

	if (dp->offset != 0) {
		if (_findnext(dp->handle, &(dp->fileinfo)) < 0) {
			dp->finished = 1;
			*result = NULL;
			return 0;
		}
	}
	dp->offset++;

	strlcpy(dp->dent.d_name, dp->fileinfo.name, _MAX_FNAME+1);
	dp->dent.d_ino = 1;
	dp->dent.d_reclen = strlen(dp->dent.d_name);
	dp->dent.d_off = dp->offset;

	memcpy(entry, &dp->dent, sizeof(*entry));

	*result = &dp->dent;

	return 0;
}

extern "C" int closedir(DIR *dp)
{
	if (!dp)
		return 0;
	_findclose(dp->handle);
	if (dp->dir)
		free(dp->dir);
	if (dp)
		free(dp);

	return 0;
}

extern "C" int rewinddir(DIR *dp)
{
	/* Re-set to the beginning */
	char *filespec;
	long handle;
	int index;

	_findclose(dp->handle);

	dp->offset = 0;
	dp->finished = 0;

	filespec = (char *)malloc(strlen(dp->dir) + 2 + 1);
	strcpy(filespec, dp->dir);
	index = strlen(filespec) - 1;
	if (index >= 0 && (filespec[index] == '/' || filespec[index] == '\\'))
		filespec[index] = '\0';
	strcat(filespec, "/*");

	if ((handle = _findfirst(filespec, &(dp->fileinfo))) < 0) {
		if (errno == ENOENT)
			dp->finished = 1;
		}
	dp->handle = handle;
	free(filespec);
	return 0;
}
#endif


/****************************************************************
 *** Service routines
 ****************************************************************/

struct afd_private {
    AFFILE **afs;			// list of AFFILEs...
    int num_afs;			// number of them
    int cur_file;			// current segment number...
};

static inline struct afd_private *AFD_PRIVATE(AFFILE *af)
{
    assert(af->v == &vnode_afd);
    return (struct afd_private *)(af->vnodeprivate);
}


/* afd_file_with_seg:
 * Returns the AFFILE for a given segment, or 0 if it isn't found.
 */

static AFFILE *afd_file_with_seg(AFFILE *af,const char *name)
{
    struct afd_private *ap = AFD_PRIVATE(af);

    for(int i=0;i<ap->num_afs;i++){
	if(af_get_seg(ap->afs[i],name,0,0,0)==0){
	    return ap->afs[i];
	}
    }
    return 0;
}

static void aff_filename(AFFILE *afd,char *buf,int buflen,int num)
{
    snprintf(buf,buflen,"%s/file_%03d.aff",afd->fname,num);
}

/* Return 1 if a file is an AFF file */
static int afd_identify_file(const char *filename,int exists)
{
    if(filename==0 || strlen(filename)==0) return 0;	// zero-length filenames aren't welcome
    if(strncmp(filename,"file://",7)==0){
	/* Move file pointer past file:// then find a '/' and take the next character  */
	filename += 7;
	while(*filename && *filename!='/'){
	    filename++;
	}
	/* At this point if *filename==0 then we never found the end of the URL.
	 * return 0, since it's not an AFF file.
	 */
	if(*filename==0) return 0;

	/* So *filename must == '/' */
	assert(*filename == '/');
	filename++;
    }
    if(exists && access(filename,R_OK)!=0) return 0;	// needs to exist and it doesn't

    /* If it ends with a '/', remove it */
    char *fn = (char *)malloc(strlen(filename)+1);
    strcpy(fn,filename);
    char *lastc = fn + strlen(fn) - 1;
    if(*lastc=='/') *lastc = '\000';

    /* If filename exists and it is a dir, it needs to end afd */
    struct stat sb;
    if(stat(fn,&sb)==0){
	if((sb.st_mode & S_IFMT)==S_IFDIR){
	    if(af_ext_is(fn,"afd")){
		free(fn);
		return 1;
	    }
	}
	free(fn);
	return 0;			//
    }
    /* Doesn't exist. Does it end .afd ? */
    if(af_ext_is(fn,"afd")){
	free(fn);
	return 1;
    }
    free(fn);
    return 0;
}




/* Add a file to the AFF system.
 * if fname==0, create a new one and copy over the relevant metadata...
 */
static int afd_add_file(AFFILE *af,const char *fname_)
{
    struct afd_private *ap = AFD_PRIVATE(af);
    const char *segs_to_copy[] = {AF_BADFLAG,
				  AF_CASE_NUM,
				  AF_IMAGE_GID,
				  AF_ACQUISITION_ISO_COUNTRY,
				  AF_ACQUISITION_COMMAND_LINE,
				  AF_ACQUISITION_DATE,
				  AF_ACQUISITION_NOTES,
				  AF_ACQUISITION_DEVICE,
				  AF_ACQUISITION_TECHNICIAN,
				  AF_DEVICE_MANUFACTURER,
				  AF_DEVICE_MODEL,
				  AF_DEVICE_SN,
				  AF_DEVICE_FIRMWARE,
				  AF_DEVICE_SOURCE,
				  AF_CYLINDERS,
				  AF_HEADS,
				  AF_SECTORS_PER_TRACK,
				  AF_LBA_SIZE,
				  AF_HPA_PRESENT,
				  AF_DCO_PRESENT,
				  AF_LOCATION_IN_COMPUTER,
				  AF_DEVICE_CAPABILITIES,
				  0};

    char fname[MAXPATHLEN+1];
    memset(fname,0,sizeof(fname));
    if(fname_){
	strlcpy(fname,fname_,sizeof(fname));
    }
    else {
	aff_filename(af,fname,sizeof(fname),ap->num_afs);
    }

    int new_file = access(fname,F_OK)!=0;	// Is this a new file?

    AFFILE *af2 = af_open(fname,af->openflags|AF_NO_CRYPTO,af->openmode);
    if(af2==0){
	(*af->error_reporter)("open(%s,%d,%d) failed: %s\n",
			      fname,af->openflags,af->openmode,strerror(errno));
	return -1;			// this is bad
    }

    ap->num_afs += 1;
    ap->afs = (AFFILE **)realloc(ap->afs,sizeof(AFFILE *) * ap->num_afs);
    ap->afs[ap->num_afs-1] = af2;

    if(new_file){
	/* Copy over configuration from AFD vnode*/
	af_enable_compression(af2,af->compression_type,af->compression_level);
	af_set_pagesize(af2,af->image_pagesize);		//
	af_set_sectorsize(af2,af->image_sectorsize);
	af_update_seg(af,AF_AFF_FILE_TYPE,0,(const u_char *)"AFD",3);

	/* If this is the second file, copy over additional metadata from first... */
	if(ap->num_afs>1){
	    AFFILE *af0 = ap->afs[0];
	    memcpy(af2->badflag,af0->badflag,af->image_sectorsize);
	    af2->bytes_memcpy += af->image_sectorsize;

	    for(const char **segname=segs_to_copy;*segname;segname++){
		unsigned char data[65536];	// big enough for most metadata
		size_t datalen = sizeof(data);
		uint32_t arg=0;

		if(af_get_seg(af0,*segname,&arg,data,&datalen)==0){
		    int r = af_update_seg(af2,*segname,arg,data,datalen);
		    if(r!=0){
			(*af->error_reporter)("afd_add_file: could not update %s in %s (r=%d)",
					      *segname,af_filename(af2),r);
		    }
		}
	    }
	}
    }

    return 0;
}



/****************************************************************
 *** User-visible functions.
 ****************************************************************/

static int afd_open(AFFILE *af)
{
    if(af->fname==0 || strlen(af->fname)==0) return -1;	// zero-length filenames aren't welcome

    /* If the name ends with a '/', remove it */
    char *lastc = af->fname + strlen(af->fname) - 1;
    if(*lastc=='/') *lastc = '\000';


    /* If the directory doesn't exist, make it (if we are O_CREAT) */
    struct stat sb;
    af->exists = 1;			// assume that the directory eixsts
    if(stat(af->fname,&sb)!=0){
	if((af->openflags & O_CREAT) == 0){ // flag not set
	    errno = ENOTDIR;
	    return -1;
	}
	mode_t cmask = umask(0);	// get the current umask
	umask(cmask & 077);		// make sure we will be able to write the file
	mkdir(af->fname,af->openmode|0111); // make the directory
	umask(cmask);			// put back the old mask
	af->exists = 0;			// directory doesn't exist; we had to make it.
	if(stat(af->fname,&sb)) return -1; // error if we can't stat it
    }
    /* If this is a regular file, don't open it */
    if(!S_ISDIR(sb.st_mode)){
	errno = ENOTDIR;		// needs to be a directory
	return -1;
    }


    af->maxsize = AFD_DEFAULT_MAXSIZE;
    af->vnodeprivate = (void *)calloc(1,sizeof(struct afd_private));
    struct afd_private *ap = AFD_PRIVATE(af);
    ap->afs = (AFFILE **)malloc(sizeof(AFFILE *));

    /* Open the directory and read all of the AFF files */
    DIR *dirp = opendir(af->fname);
    if(!dirp){
	return -1;			// something is wrong...
    }
    struct dirent *dp;
    while ((dp = readdir(dirp)) != NULL){
	if (af_ext_is(dp->d_name,"aff")){
	    char path[MAXPATHLEN+1];
	    strlcpy(path,af->fname,sizeof(path));
	    strlcat(path,"/",sizeof(path));
	    strlcat(path,dp->d_name,sizeof(path));
	    if(afd_add_file(af,path)){
		closedir(dirp);
		return -1;
	    }
	}
    }
    closedir(dirp);
    if(ap->num_afs==0 && af->exists){
	snprintf(af->error_str,sizeof(af->error_str),".afd directory contains no .aff files!");
	return -1;
    }
    return 0;				// "we were successful"
}


static int afd_close(AFFILE *af)
{
    struct afd_private *ap = AFD_PRIVATE(af);

    /* Close all of the subfiles, then free the memory, then close this file */
    for(int i=0;i<ap->num_afs;i++){
	ap->afs[i]->image_size = af->image_size; // set each to have correct imagesize
	af_close(ap->afs[i]);		// and close each file
    }
    free(ap->afs);
    memset(ap,0,sizeof(*ap));		// clean object reuse
    free(ap);				// won't need it again
    return 0;
}


#if !defined(WIN32) || defined(HAVE__MINGW_H)
static uint64_t max(uint64_t a,uint64_t b)
{
    return a > b ? a : b;
}
#endif

static int afd_vstat(AFFILE *af,struct af_vnode_info *vni)
{
    struct afd_private *ap = AFD_PRIVATE(af);
    memset(vni,0,sizeof(*vni));		// clear it

    /* See if there is some device that knows how big the disk is */
    if(ap->num_afs>0){
	af_vstat(ap->afs[0],vni);	// get disk free bytes
    }

    /* Get the file with the largest imagesize from either the
     * AFD or any of the sub AFDs...
     */
    vni->imagesize = af->image_size;
    for(int i=0;i<ap->num_afs;i++){
	vni->imagesize = max(vni->imagesize,ap->afs[i]->image_size);
    }
    vni->has_pages = 1;
    vni->supports_metadata = 1;
    return 0;
}

static int afd_get_seg(AFFILE *af,const char *name,uint32_t *arg,unsigned char *data,
		       size_t *datalen)
{
    AFFILE *af2 = afd_file_with_seg(af,name);
    if(!af2)
	{ errno = ENOENT; return -1; }

    return af_get_seg(af2,name,arg,data,datalen); // use this one
}


static int afd_get_next_seg(AFFILE *af,char *segname,size_t segname_len,uint32_t *arg,
			unsigned char *data,size_t *datalen_)
{
    /* See if there are any more in the current segment */
    struct afd_private *ap = AFD_PRIVATE(af);
    while (ap->cur_file < ap->num_afs) {
	int r = af_get_next_seg(ap->afs[ap->cur_file],segname,segname_len,arg,data,datalen_);
	if(r!=AF_ERROR_EOF){		// if it is not EOF
	    return r;
	}
	ap->cur_file++;			// advance to the next file
	if(ap->cur_file < ap->num_afs){	// rewind it to the beginning
	    af_rewind_seg(ap->afs[ap->cur_file]);
	}
    } while(ap->cur_file < ap->num_afs);
    return AF_ERROR_EOF;		// really made it to the end
}


/* Rewind all of the segments */
static int afd_rewind_seg(AFFILE *af)
{
    struct afd_private *ap = AFD_PRIVATE(af);
    ap->cur_file = 0;
    for(int i=0;i<ap->num_afs;i++){
	af_rewind_seg(ap->afs[i]);
    }
    return 0;
}



/* Update:
 * If this segment is in any of the existing files, update it there.
 * Otherwise, if the last file isn't too big, add it there.
 * Otherwise, ada a new file.
 */
static int afd_update_seg(AFFILE *af, const char *name,
		    uint32_t arg,const u_char *value,uint32_t vallen)

{
    struct afd_private *ap = AFD_PRIVATE(af);
    AFFILE *af2 = afd_file_with_seg(af,name);
    if(af2){
	return af_update_seg(af2,name,arg,value,vallen); // update where it was found
    }
    /* Segment doesn't exist anywhere... */
    /* Append to the last file if there is space and a space limitation... */
    if(ap->num_afs>0){
	AFFILE *af3 = ap->afs[ap->num_afs-1];
	FILE *aseg = af3->aseg;

	uint64_t offset = ftello(aseg);
	fseeko(aseg,0,SEEK_END);

	uint64_t len = ftello(aseg);
	fseeko(aseg,offset,SEEK_SET);

	if((len + vallen + 1024 < af->maxsize) && (af->maxsize!=0)){
	    /* It should fit with room left over! */
	    return af_update_seg(af3,name,arg,value,vallen);
	}
    }

    /* Create a new file and add the segment to it.*/
    if(afd_add_file(af,0)) return -1;
    AFFILE *af4 = ap->afs[ap->num_afs-1]; // this is the one just added
    return af_update_seg(af4,name,arg,value,vallen);
}

int afd_del_seg(AFFILE *af,const char *segname)
{
    AFFILE *af2 = afd_file_with_seg(af,segname);
    if(!af2)
	{ errno = ENOENT; return -1; }

    return af_del_seg(af2,segname);
}


struct af_vnode vnode_afd = {
    AF_IDENTIFY_AFD,		//
    AF_VNODE_TYPE_COMPOUND|AF_VNODE_TYPE_RELIABLE,		//
    "AFF Directory",
    afd_identify_file,
    afd_open,			// open
    afd_close,			// close
    afd_vstat,			// vstat
    afd_get_seg,		// get_seg
    afd_get_next_seg,		// get_next_seg
    afd_rewind_seg,		// rewind_seg
    afd_update_seg,		// update_seg
    afd_del_seg,		// del_seg
    0,				// read
    0				// write
};
