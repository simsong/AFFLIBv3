/*
 * afsegment.cpp
 *
 * segment manipulation tool
 */

/*
 * Copyright (c) 2005-2006
 *	Simson L. Garfinkel and Basis Technology, Inc. 
 *      All rights reserved.
 *
 * This code is derrived from software contributed by
 * Simson L. Garfinkel
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. [omitted]
 * 4. Neither the name of Simson Garfinkel, Basis Technology, or other
 *    contributors to this program may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY SIMSON GARFINKEL, BASIS TECHNOLOGY,
 * AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL SIMSON GARFINKEL, BAIS TECHNOLOGy,
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.  
 */


#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"

#include <limits.h>

#ifdef HAVE_REGEX_H
extern "C" {
#include <regex.h>
}
#endif

#include <algorithm>
#include <cstdlib>
#include <vector>
#include <string>

#ifdef HAVE_CSTRING
#include <cstring>
#endif

using namespace std;


const char *progname = "afsegment";

int opt_create = 0;
int opt_quad = 0;
int opt_arg  = 0;
int opt_verbose = 0;
int filecount = 0;
int opt_debug = 0;
int opt_x = 0;

void usage()
{
    printf("afsegment version %s\n",PACKAGE_VERSION);
#ifdef REG_EXTENDED
    printf("usage: afsegment [options] file1.aff [file2.aff ...]\n");
    printf("options:\n");
    printf("    -c              Create AFF files if they do not exist\n");
    printf("    -ssegval        Sets the value of a segment; may be repeated\n");
    printf("    -psegname       Prints the contents of the segment name for each file\n");
    printf("    -V              Just print the version number and exit.\n");    
    printf("    -dname          Delete segment 'name'\n");
    printf("    -h, -?          Print this message\n");
    printf("    -Q              interpert 8-byte segments as a 64-bit value\n");
    printf("    -A              Print the 32-bit arg, not the segment value\n");
    printf("    -x              Print the segment as a hex string\n");
    printf("\n");
    printf("Values for segval:\n");
    printf("\n");
    printf("Setting the segment values:\n");
    printf("    -sname=-        Take the new value of segment 'name' from stdin\n");
    printf("    -sname=val      Sets segment 'name' to be 'val'  \n");
    printf("    -sname=<val     Sets segment 'name' to be contents of file 'val'\n");
    printf("\n");
    printf("Setting the segment args:\n");
    printf("    -sname/arg       Sets segment 'name' arg to be 'arg'  (may be repeated)\n");
    printf("\n");
    printf("Setting both the segment value and the arg:\n");
    printf("    -sname/arg=val   Sets both arg and val for segment 'name'\n");
    printf("    -sname/arg=<file Sets the arg and take contents from file 'file'\n");
    printf("    -sname/arg=-     Sets the arg of segment 'name' and take the contents from stdin\n");
    printf("\n");
    printf("Note: All deletions are done first, then all updates. Don't specify the\n");
    printf("same segment twice on one command line.\n");
#else
    printf("afsegment requires a functioning regex package to be installed\n");
#endif    
    exit(0);
}

#ifdef REG_EXTENDED
int get_segment_from_file(AFFILE *af,const char *segname,uint32_t arg,FILE *in)
{
    u_char *value = (u_char *)malloc(0);
    int  value_len = 0;

    while(!feof(in)){
	char buf[4096];
	int  count;
	count = fread(buf,1,sizeof(buf),in);
	if(count>0){
	    value = (u_char *)realloc(value,value_len+count);
	    memcpy(value+value_len,buf,count);
	    value_len += count;
	}
    }
    int r = af_update_seg(af,segname,arg,value,value_len);
    free(value);
    return r;
}


void update_segment(AFFILE *af,const char *segname,
		    const char *argstr,const char *segval)
{
    uint32_t arg = 0;

    if(strlen(argstr)>1) arg = atoi(argstr+1);

    if(!strcmp(segval,"=-")){
	get_segment_from_file(af,segname,arg,stdin);
	return;
    }
    if(!strncmp(segval,"=<",2)){
	FILE *f = fopen(segval+2,"rb");
	if(!f) err(1,"fopen(%s)",segval+2);
	get_segment_from_file(af,segname,arg,f);
	fclose(f);
	return;
    }
    segval++;				// skip past the "="
    int r = af_update_seg(af,segname,arg,(const u_char *)segval,strlen(segval));
    if(r) warn("af_update(%s,%s) ",af_filename(af),segname);
}


char *make_re_string(const char *buf,regmatch_t *match,int num)
{
    int len = match[num].rm_eo - match[num].rm_so;
    char *ret = (char *)malloc(len+1);
    memcpy(ret,buf+match[num].rm_so,len);
    ret[len] = '\000';
    return ret;
}


vector<string>del_segs;
vector<string>new_segs;
vector<string>print_segs;
int flags=O_RDONLY;
int openmode = 0666;
regex_t re;

void process(const char *fn)
{
    AFFILE *af = af_open(fn,flags,openmode);
    if(af){
	vector<string>::iterator i;

	for(i=del_segs.begin();i!=del_segs.end();i++){
	    if(af_del_seg(af,i->c_str())){
		warnx("af_del_seg(%s): cannot delete segment '%s' ",fn,i->c_str());
	    }
	    else {
		printf("%s: '%s' deleted\n",fn,i->c_str());
	    }
	}
	for(i=new_segs.begin();i!=new_segs.end();i++){
	    regmatch_t match[10];
	    memset(match,0,sizeof(match));
	    if(regexec(&re,i->c_str(),10,match,0)==0){
		char *segname = make_re_string(i->c_str(),match,1);
		char *argstr  = make_re_string(i->c_str(),match,2);
		char *segval  = make_re_string(i->c_str(),match,3);
		update_segment(af,segname,argstr,segval);
		free(segname);
		free(argstr);
		free(segval);
	    }
	}
	for(i=print_segs.begin();i!=print_segs.end();i++){
	    size_t len = 0;
	    const char *segname = i->c_str();
	    if(opt_debug) fprintf(stderr," %s: \n",segname);
	    unsigned char *buf=0;
	    if(af_get_seg(af,segname,0,0,&len)){
#if HAVE_ISATTY
		if(isatty(fileno(stdout))){
		    fprintf(stderr,"%s: segment %s not found\n",fn,segname);
		    continue;
		}
#endif
		if(opt_debug) fprintf(stderr,"  <<not found>>\n");
		continue;
	    }
		
	    buf = (u_char *)malloc(len+1);
	    if(!buf) err(1,"malloc");
	    uint32_t arg = 0;
	    buf[len] = 0;
	    if(af_get_seg(af,segname,&arg,buf,&len)){
		af_err(1,"af_get_seg"); // this shoudln't fail here
		free(buf);
		continue;
	    }
	    if(opt_debug) fprintf(stderr," arg=%"PRIu32" len=%zd\n",arg,len);
	    int p = 1;
	    
	    if(filecount>1) printf("%s:",fn);
	    if(print_segs.size()>1) printf("%s=",segname);
	    if(opt_quad && len==8){
		uint64_t quad = af_decode_q(buf);
		printf("%"I64u"\n",quad);
		p = 0;
	    }
	    
	    if(opt_arg){
		printf("%"PRIu32"\n",arg);
		p = 0;
	    }
	    
	    if(p){
		for(u_int i=0;i<len;i++){
		    putchar(buf[i]);
		}
	    }
	    if(filecount>1) printf("\n");
	    fflush(stdout);
	    if(buf) free(buf);
	}
	af_close(af);
	if(opt_x) printf("\n");
    }
    else {
	af_err(1,"af_open(%s) failed:",fn);
    }
}

int main(int argc,char **argv)
{

    int ch;
    while ((ch = getopt(argc, argv, "cd:Vp:s::h?QADx")) != -1) {
	switch (ch) {
	case 'c':
	    flags |= O_CREAT;
	    openmode = 0666;
	    break;
	case 'Q': opt_quad=1;break;
	case 'A': opt_arg=1;break;
	case 'd':
	    if(optarg==0) usage();
	    del_segs.push_back(optarg); flags |= O_RDWR;break;
	case 'D':
	    opt_debug=1;
	    break;
	case 'p': 
	    if(optarg==0) usage();
	    print_segs.push_back(optarg); break;
	case 's': 
	    if(optarg==0) usage();
	    if(strlen(optarg)==0) usage();
	    new_segs.push_back(optarg); flags |= O_RDWR;break;
	case 'x':
	    opt_x++;
	    break;
	case 'h':
	case '?':
	default:
	    usage();
	    exit(0);
	case 'V':
	    printf("%s version %s\n",progname,PACKAGE_VERSION);
	    exit(0);
	}
    }
    argc -= optind;
    argv += optind;

    if(argc<1){
	usage();
    }

    if(regcomp(&re,"([^/=]*)(/[0-9]+)?(=.*)?",REG_EXTENDED|REG_ICASE)){
	err(1,"regcomp");
    }

    filecount = argc;
    while(*argv){
	fflush(stdout);
	if(opt_debug) fprintf(stderr,"%s:\n",*argv);
	process(*argv);
	argv++;
	argc--;
    }
    exit(0);
}
#else
int main(int argc,char **argv)
{
    usage();
    exit(1);
}
#endif
