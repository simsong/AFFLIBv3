/*
 * vnode_aff.cpp:
 *
 * Functions for the manipulation of AFF files...
 *
 * Distributed under the Berkeley 4-part license
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"
#include "vnode_s3.h"
#include "s3_glue.h"

static int s3_close(AFFILE *af);

/* Return 1 if a file is an S3 URL */
static int s3_identify_file(const char *filename,int exists)
{
    if(strlen(filename)<5 || strncmp(filename,"s3://",5)!=0) return 0; // not a valid URL
#ifdef USE_S3
    if(exists==0) return 1;		// don't need to check for existence; just return true

    /* See if it exists */
    AFFILE *af = af_open_with(filename,O_RDONLY,0,&vnode_s3);	// can we open it with s3?
    if(!af) return 0;			// can't open it
    s3_close(af);
#endif
    return 1;				// it's legit (or S3 support is not compiled in)
}

#ifdef USE_S3
#define S3_HEADER_ARG  AMAZON_METADATA_PREFIX "arg" // XML metadata where the arg is stored


using namespace std;
using namespace s3;

/****************************************************************
 *** Service routines
 ****************************************************************/

class s3_private {
public:
    s3_private():lbr(0) {}
    ~s3_private(){
	if(lbr) delete lbr;
    }
    string bucket;
    string path;			// of the S3 root object
    string current_seg;			// the segment we are currently on
    ListBucketResult *lbr;		// if we have one
};

static inline struct s3_private *S3_PRIVATE(AFFILE *af)
{
    assert(af->v == &vnode_s3);
    return (s3_private *)(af->vnodeprivate);
}


/****************************************************************
 *** User-visible functions.
 ****************************************************************/

#include <regex.h>
static int s3_open(AFFILE *af)
{
    /* Set debug variable */
    if(getenv(S3_DEBUG)){
	s3_debug = atoi(getenv(S3_DEBUG));
#ifdef HAVE_ERR_SET_EXIT
	err_set_exit(s3_audit);
#endif
    }

    /* Create the bucket if it doesn't exist */
    aws_access_key_id     = getenv(AWS_ACCESS_KEY_ID);
    aws_secret_access_key = getenv(AWS_SECRET_ACCESS_KEY);

    if(!aws_access_key_id) fprintf(stderr,"s3: AWS_ACCESS_KEY_ID not defined\n");
    if(!aws_secret_access_key) fprintf(stderr,"s3: AWS_SECRET_ACCESS_KEY not defined\n");
    if(!aws_access_key_id || !aws_secret_access_key) return -1; /* can't open */

    /* URL host becomes bucket */
    char bucket[1024]; memset(bucket,0,sizeof(bucket));
    strcpy(bucket,af->hostname);

    if(strlen(bucket)==0){
	const char *b = getenv(S3_DEFAULT_BUCKET);
	if(!b){
	    fprintf(stderr,"s3: S3_DEFAULT_BUCKET not defined and no bucket in URL.\n");
	    return -1;
	}
	strlcpy(bucket,b,sizeof(bucket));
    }
    if(strlen(af->fname)==0){
	fprintf(stderr,"s3: No path specified in URL '%s'\n",af->fname);
	return -1;
    }

    af->vnodeprivate = (void *)new s3_private();
    struct s3_private *sp =S3_PRIVATE(af);
    sp->bucket = bucket;
    sp->path   = string(af->fname) + "/";

    /* If we are opening with O_CREAT and O_EXCL and the pagesize exists, then the
     * file was already created. Return an error.
     */
    bool exists = af_get_seg(af,AF_PAGESIZE,0,0,0)==0;

    if((af->openflags & O_CREAT) && (af->openflags & O_EXCL) && exists){
	errno = EEXIST;
	return -1;
    }

    /* If we are opening without O_CREAT and the pagesize does not exist, then the
     * file was not created. Return an error.
     */
    if((af->openflags & O_CREAT)==0 && !exists){
	errno = ENOENT;
	return -1;
    }
    return 0;				// "we were successful"
}


static int s3_close(AFFILE *af)
{
    struct s3_private *sp =S3_PRIVATE(af);
    if(sp) delete sp;
    return 0;
}


static int s3_vstat(AFFILE *af,struct af_vnode_info *vni)
{
    memset(vni,0,sizeof(*vni));		// clear it

    vni->has_pages = 1;
    vni->supports_metadata = 1;
    if(af->image_size==0) af_read_sizes(af); // wasn't set?
    vni->imagesize = af->image_size;
    return 0;
}

static int s3_get_seg(AFFILE *af,const char *name,uint32_t *arg,unsigned char *data,
		       size_t *datalen)
{
    /* TK: Don't get the whole object if we just want the size or the argument.
     * Use Content-Range: as documented at http://docs.amazonwebservices.com/AmazonS3/2006-03-01/
     **/

    struct s3_private *sp =S3_PRIVATE(af);
    sp->current_seg = name;
    uint content_length = 0;

    response_buffer *r = 0;

    if(data) r = object_get(sp->bucket,sp->path + sp->current_seg,0);
    else     r = object_head(sp->bucket,sp->path + sp->current_seg,0);

    if(r==0) return -1;			// no response was returned?

    if(r->result!=200){			// segment not found
	delete r;
	return -1;
    }

    /* Check for metadata headers */
    if(arg) *arg=0;			// default
    for(map<string,string>::const_iterator i = r->rheaders.begin();
	i != r->rheaders.end();
	i++){
	if( i->first == S3_HEADER_ARG && arg){
	    *arg = atoi(i->second.c_str());
	    continue;
	}
	if( i->first == S3_CONTENT_LENGTH){
	    content_length = atoi(i->second.c_str());
	}
    }

    if(datalen==0) {			// no clue the size of the data...
	delete r;
	return 0;
    }
    if(*datalen==0){
	*datalen = data ? r->len : content_length; // use content_length if not getting data
	delete r;
	return 0;			// datalen didn't have enough room
    }
    if(*datalen < r->len){
	delete r;
	return -2;			// datalen not being enough
    }
    if(data) memcpy(data,r->base,r->len);
    *datalen = r->len;
    delete r;
    return 0;
}


static int s3_get_next_seg(AFFILE *af,char *segname,size_t segname_len,uint32_t *arg,
			unsigned char *data,size_t *datalen)
{
    memset(segname,0,segname_len);

    struct s3_private *sp =S3_PRIVATE(af);

    if(sp->lbr && sp->lbr->contents.size()==0){	// this one is empty
	delete sp->lbr;
	sp->lbr = 0;
    }
    if(sp->lbr==0){			// need to get a new lbr..
	s3_result *r = list_bucket(sp->bucket,sp->path,sp->path + sp->current_seg,0);
	if(r->lbr==0){delete r;return -1;}	// hm... didn't get the right response?
	sp->lbr = r->lbr;		// grab the lbr
	r->lbr = 0;			// and we won't let it be freed here.
	delete r;
    }

    if(sp->lbr->contents.size()==0){
	delete sp->lbr;
	sp->lbr = 0;
	return -1;	// nothing left
    }

    sp->current_seg= sp->lbr->contents[0]->Key.substr(sp->path.size());

    /* Set up the fields */
    memset(segname,0,segname_len);
    if(segname_len > sp->current_seg.size()){
	strcpy(segname,sp->current_seg.c_str());
    }
    if(datalen) *datalen = sp->lbr->contents[0]->Size;

    sp->lbr->contents.erase(sp->lbr->contents.begin());	// remove the first item

    /* If the user has asked for either the arg or the data, we need to get the object */
    if(arg || data) return s3_get_seg(af,segname,arg,data,datalen);
    return 0;				// otherwise, return success
}


/* Rewind all of the segments */
static int s3_rewind_seg(AFFILE *af)
{
    struct s3_private *sp =S3_PRIVATE(af);
    sp->current_seg = "";
    if(sp->lbr){
	delete sp->lbr;
	sp->lbr = 0;
    }
    return 0;
}



/* Update:
 * S3 implementation ignores append
 */
static int s3_update_seg(AFFILE *af, const char *name,
		    uint32_t arg,const u_char *value,uint32_t vallen)

{
    struct s3_private *sp =S3_PRIVATE(af);
    char metabuf[64];
    snprintf(metabuf,sizeof(metabuf),"%lu",arg);	// get the arg
    struct s3headers meta[] = {{S3_HEADER_ARG,metabuf},{0,0}};

    sp->current_seg = name;
    if(vallen==0){
	value=(const u_char *)""; // point to a null string, so object_put knows to put
    }
    return object_put(sp->bucket,sp->path + sp->current_seg,(const char *)value,vallen,meta);
}

int s3_del_seg(AFFILE *af,const char *segname)
{
    struct s3_private *sp =S3_PRIVATE(af);
    sp->current_seg = segname;
    return object_rm(sp->bucket,sp->path + sp->current_seg);
}


struct af_vnode vnode_s3 = {
    AF_IDENTIFY_S3,			//
    AF_VNODE_TYPE_RELIABLE,		//
    "s3.amazonaws.com",
    s3_identify_file,
    s3_open,				// open
    s3_close,				// close
    s3_vstat,				// vstat
    s3_get_seg,				// get_seg
    s3_get_next_seg,			// get_next_seg
    s3_rewind_seg,			// rewind_seg
    s3_update_seg,			// update_seg
    s3_del_seg,				// del_seg
    0,					// read
    0					// write
};
#else
static int s3_cantopen(AFFILE *af)
{
    err(1,"AFFLIB s3: Request to open %s, but S3 support is not compiled in.",af_filename(af));
    return -1;
}

struct af_vnode vnode_s3 = {
    AF_IDENTIFY_S3,			//
    AF_VNODE_TYPE_RELIABLE,		//
    "s3.amazonaws.com",
    s3_identify_file,
    s3_cantopen,			// open
    0,					// close
    0,					// vstat
    0,					// get_seg
    0,					// get_next_seg
    0,					// rewind_seg
    0,					// update_seg
    0,					// del_seg
    0,					// read
    0					// write
};


#endif // USE_S3

