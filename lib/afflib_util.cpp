/*
 * utility functions used by AFFLIB.
 * These functions do not actually read or write data into the AFF File.
 * Distributed under the Berkeley 4-part license.
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"

#ifndef HAVE_ERR
#include <stdarg.h>
void err(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
  fprintf(stderr,": %s\n",strerror(errno));
  exit(eval);
}
#endif

void af_err(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
  if(af_error_str[0]) fprintf(stderr,": %s",af_error_str);
  if(errno) fprintf(stderr,": %s",strerror(errno));
  fputc('\n',stderr);
  exit(eval);
}


#ifndef HAVE_ERRX
#include <stdarg.h>
void errx(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  fprintf(stderr,"%s\n",strerror(errno));
  va_end(ap);
  exit(eval);
}
#endif

#ifndef HAVE_WARN
#include <stdarg.h>
void	warn(const char *fmt, ...)
{
    va_list args;
    va_start(args,fmt);
    vfprintf(stderr,fmt, args);
    fprintf(stderr,": %s",strerror(errno));
}
#endif

#ifndef HAVE_WARNX
#include <stdarg.h>
void warnx(const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
}
#endif




/*
 * af_hexbuf:
 * Turn a binay string into a hex string, optionally with spaces.
 */

const char *af_hexbuf(char *dst,int dst_len,const unsigned char *bin,int bytes,int flag)
{
    int charcount = 0;
    const char *start = dst;		// remember where the start of the string is
    const char *fmt = (flag & AF_HEXBUF_UPPERCASE) ? "%02X" : "%02x";

    *dst = 0;				// begin with null termination
    while(bytes>0 && dst_len > 3){
	sprintf(dst,fmt,*bin); // convert the next byte
	dst += 2;
	bin += 1;
	dst_len -= 2;
	bytes--;
	charcount++;			// how many characters

	if((flag & AF_HEXBUF_SPACE4) && charcount%2==0){
	    *dst++ = ' ';
	    *dst   = '\000';
	    dst_len -= 1;
	}
    }
    return start;			// return the start
}


/* Add commas
 */
const char *af_commas(char buf[64],int64_t val)
{
    char tmp[64];
    char t2[64];
    int  negative = 0;

    buf[0] = 0;
    if(val==0){
	strcpy(buf,"0");
    }
    if(val<0){
	negative = 1;
	val = -val;
    }

    while(val>0){
	int digits = val % 1000;		// get the residue
	val = val / 1000;		// and shift what's over

	if(val>0){			// we will still have more to do
	    sprintf(tmp,",%03d",digits);	// so pad it with zeros and a comma
	}
	else {
	    sprintf(tmp,"%d",digits);	// otherwise just get the value
	}
	strcpy(t2,buf);			// copy out the buffer
	strcpy(buf,tmp);		// copy in what we just did
	strcat(buf,t2);			// and put back what was there
    }
    if(negative){
	strcpy(t2,buf);
	strcpy(buf,"-");
	strcat(buf,t2);
    }
    return buf;
}

uint64_t af_decode_q(unsigned char buf[8])
{
    struct aff_quad *q = (struct aff_quad *)buf;		// point q to buf.

    assert(sizeof(*q)==8);		// be sure!
    return (((uint64_t)ntohl(q->high)) << 32) + ((uint64_t)ntohl(q->low));
}

/* parse the segment number.
 * The extra %c picks up characters that might be after the number,
 * so that page5_hash doesn't match for page5.
 */
int64_t	af_segname_page_number(const char *name)
{
#ifdef KERNEL_LIBRARY
#define PAGE_NAME "page"
	if(_strnicmp(name,PAGE_NAME,strlen(PAGE_NAME))==0)
	{
		int64_t pagenum;
		for (int i=strlen(PAGE_NAME);i<strlen(name);i++)
			if (!isdigit(name[i])) return -1;

		pagenum = _atoi64(name+strlen(PAGE_NAME));
		return pagenum;
	}
#define SEG_NAME "seg"
	if(_strnicmp(name,SEG_NAME,strlen(SEG_NAME))==0)
	{
		int64_t pagenum;
		for (int i=strlen(SEG_NAME);i<strlen(name);i++)
			if (!isdigit(name[i])) return -1;

		pagenum = _atoi64(name+strlen(SEG_NAME));
		return pagenum;
	}
	return -1;
#else
    int64_t pagenum;
    char  ch;
    if(sscanf(name,AF_PAGE"%c",&pagenum,&ch)==1){
	return pagenum;			// new-style page number
    }
    if(sscanf(name,AF_SEG_D"%c",&pagenum,&ch)==1){
	return pagenum;			// old-style page number
    }
    return -1;
#endif
}

int64_t	af_segname_hash_page_number(const char *name,char *hash,int hashlen)
{
    char copy[AF_MAX_NAME_LEN];
    const char *cc = strchr((char *)name,'_');
    if(!cc) return -1;			// not possibly correct
    strlcpy(copy,name,sizeof(copy));
    char *dd = strchr(copy,'_');
    if(!dd) return -1;		        // really weird; shouldn't happen
    *dd++ = '\000';			// terminate at _
    if(strcmp(dd,"md5")!=0) return -1;	// not a valid hash
    int64_t page = af_segname_page_number(copy);
    if(page<0) return -1;		// wasn't what we wanted
    strlcpy(hash,dd,hashlen);
    return page;
}

int af_hasmeta(const char *infile)
{
    /* return 1 if the string has shell metacharacters */
    for(const char *cc = infile;*cc;cc++){
	switch(*cc){
	case '?': return 1;
	case '*': return 1;
	case '&': return 1;
	case '`': return 1;
	case '(': return 1;
	case ')': return 1;
	}
    }
    return 0;
}

/* It is a filestream if the filename begins file:// or has no "://" in it */
int af_is_filestream(const char *filename)
{
    if(strncmp(filename,"file://",7)==0) return 1;
    if(strstr(filename,"://")==0) return 1;
    return 0;
}






#ifndef HAVE_STRLCPY
size_t strlcpy(char *dest,const char *src,size_t dest_size)
{
    strncpy(dest,src,dest_size);
    dest[dest_size-1] = '\000';
    return strlen(dest);
}
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dest,const char *src,size_t dest_size)
{
    int dest_len = strlen(dest);
    int src_len  = strlen(src);
    int room     = dest_size - (dest_len +src_len+1);
    if(room>0){
	/* There is room; just copy over what we have and return */
	strcat(dest,src);
	return strlen(dest);
    }
    /* Not room; figure out how many bytes we can copy... */
    int left = dest_size - (dest_len+1);
    strncpy(dest+dest_len,src,left);
    dest[dest_len-1] = '\000';
    return strlen(dest);
}
#endif

/* Parse a URL. Allocate the parts if requested. Default protocol is "file", of course*/
void af_parse_url(const char *url,char **protocol,char **hostname,char **username,char **password,
		 int *port,char **path)
{
    const char *p1 = strstr(url,"://");
    if(!p1){
	if(protocol) *protocol = strdup("file");
	if(path)     *path     = strdup(url);
	return;
    }
    if(protocol){
	int len = p1-url;
	*protocol = (char *)malloc(len+1);
	strncpy(*protocol,url,len);
    }
    url = p1+3;		// move past ://

    const char *at = strchr(url,'@');
    if(at){					// we may have a username and/or password
	char *scratch = (char *)malloc(at-url+1);
	strncpy(scratch,url,at-url);
	scratch[at-url]='\000';
	char *colon = strchr(scratch,':');
	if(colon){
	    *colon = '\000';
	}
	if(username) *username = strdup(scratch);
	if(colon){
	    if(password) *password = strdup(colon+1);
	}
	free(scratch);
	url = at+1;
    }

    /* Process hostname if it exists */
    const char *slash = strchr(url,'/');
    if(slash){
	char *scratch = (char *)malloc(slash-url+1);
	strncpy(scratch,url,slash-url);
	scratch[slash-url]='\000';
	char *colon = strchr(scratch,':');
	if(colon){
	    *colon = '\000';
	}
	if(hostname) *hostname = strdup(scratch);
	if(colon){
	    if(port) *port = atoi(colon+1);
	}
	free(scratch);
	url = slash+1;
    }
    if(path) *path = strdup(url);	                // remember file name
}
