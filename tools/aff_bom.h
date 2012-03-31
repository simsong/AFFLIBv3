/*
 * aff_bom.h
 *
 * PUBLIC DOMAIN SOFTWARE.
 *
 * The software provided here is released by the Naval Postgraduate
 * School (NPS), an agency of the US Department of the Navy, USA.  The
 * software bears no warranty, either expressed or implied. NPS does
 * not assume legal liability nor responsibility for a User's use of
 * the software or the results of such use.  Please note that within
 * the United States, copyright protection, under Section 105 of the
 * United States Code, Title 17, is not available for any work of the
 * United States Government and/or for any works created by United
 * States Government employees. User acknowledges that this software
 * contains work which was created by NPS employee(s) and is therefore
 * in the public domain and not subject to copyright.  
 * --------------------------------------------------------------------
 *
 * Change History:
 * Simson L. Garfinkel - 2008 - Created
 */



#ifndef AFF_BOM_H
#define AFF_BOM_H

#include <algorithm>
#include <cstdlib>
#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <assert.h>
#ifdef HAVE_OPENSSL_PEM_H
#include <openssl/x509.h>
#include <openssl/pem.h>
#else
typedef void X509;
typedef void EVP_PKEY;
typedef void BIO;
#define BIO_free free
#endif



class outelement {
public:
    outelement(){}
    AFFILE *af;			// where output goes
    aff::seglist segs; // list of existing segments in output
};
    typedef std::vector<outelement> outlist;

int  parse_chain(const std::string &name);
int  highest_chain(aff::seglist &slist);

#ifdef USE_AFFSIGS
class aff_bom {
    X509 *cert;
    EVP_PKEY *privkey;
    char *notes;
    bool bom_open;
public:
    static void make_hash(u_char seghash[32], uint32_t arg,const char *segname,
		     const u_char *pagebuf, uint32_t pagesize);
    bool opt_note;
    BIO *xml;
    aff_bom(bool flag):cert(0),privkey(0),notes(0),bom_open(false),opt_note(flag),xml(0) { }
    ~aff_bom(){
	assert(!bom_open);
	if(notes) free(notes);
	if(xml) BIO_free(xml);
    }
    int read_files(const char *cert_file,const char *key_file);	// returns 0 if success
    void add(const char *segname,int sigmode,const u_char *seghash,size_t seghash_len); // add to BOM
    int add(AFFILE *af,const char *segname); // get the seg, hash it, and add it to the BOM
    void close();			// close the BoM
    int  write(AFFILE *af,aff::seglist &segments);	// write the BoM
    char *get_notes();
};
#endif

#endif
