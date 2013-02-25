/*
 * utils.cpp:
 *
 * Some handy utilities for working with AFF
 *
 * Distributed under the Berkeley 4-part license
 */


#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"
#include "utils.h"
#ifdef HAVE_ERR_H
#include "err.h"
#endif

#include <string>
#ifdef HAVE_CSTRING
#include <cstring>
#endif

#ifdef HAVE_READLINE_READLINE_H
#include <readline/readline.h>
#endif

namespace aff {

    bool ends_with(const char *buf,const char *with)
    {
	if(buf && with){
	    size_t buflen = strlen(buf);
	    size_t withlen = strlen(with);
	    if(buflen>withlen && strcmp(buf+buflen-withlen,with)==0) return 1;
	}
	return 0;
    }

#ifdef HAVE_STL
    /** Given argc and argv, return a string with the command line */
    std::string command_line(int argc,char **argv) {
	std::string command = "";
	for(int i=0;i<argc;i++){
	    if(i>0) command += " ";
	    command += argv[i];
	}
	return command;
    }
    bool ends_with(const std::string &buf,const std::string &with)
    {
	return ends_with(buf.c_str(),with.c_str());
    }


    /* Given an AFFILE, return a seglist.
     * Returns -1 if failure, 0 if success.
     */
    int seglist::get_seglist(AFFILE *af)
    {
	if(af_rewind_seg(af)) return -1;
	char name_[AF_MAX_NAME_LEN];
	size_t len_=0;
	uint32_t arg_=0;
	while(af_get_next_seg(af,name_,sizeof(name_),&arg_,0,&len_)==0){
	    // We shouldn't have 0-len segment names, but we do in some files.
	    // Don't copy these segments.
	    if(strlen(name_)>0){
		seginfo si(name_,len_,arg_);
		push_back(si);
	    }
	}
	return 0;
    }

    bool seglist::has_signed_segments()
    {
	for(seglist::const_iterator seg = begin(); seg!=end() ;seg++){
	    if(ends_with(seg->name.c_str(),AF_SIG256_SUFFIX)){
		return true;
	    }
	}
	return false;
    }


    bool seglist::contains(std::string segname)
    {
	for(std::vector<seginfo>::const_iterator i = begin(); i!=end(); i++){
	    if(i->name == segname) return true;
	}
	return false;
    }

#endif
}

