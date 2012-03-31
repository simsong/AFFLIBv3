/*
 * afsign.cpp:
 *
 * Sign an existing AFF file.
 * This file is a work of a US government employee and as such is in the Public domain.
 * Simson L. Garfinkel, March 12, 2012
 */

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"

#ifdef USE_AFFSIGS

#include "utils.h"
#include "base64.h"

#include <stdio.h>
#include <algorithm>
#include <vector>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509.h>


#include "aff_bom.h"

int opt_note = 0;
const char *opt_sign_key_file = 0;
const char *opt_sign_cert_file = 0;

using namespace std;
using namespace aff;

const char *progname = "afsign";

void usage()
{
    printf("%s version %s\n",progname,PACKAGE_VERSION);
    printf("usage: %s [options] filename.aff\n",progname);
    printf("This program will:\n");
    printf("  * Sign each segment if there are no segment signatures.\n");
    printf("  * Write signed chain-of-custody Bill of Materials segment.\n");
    printf("\nSignature Options:\n");
    printf("   -k filename.key   = specify private key for signing\n");
    printf("   -c filename.cer   = specify a X.509 certificate that matches the private key\n");
    printf("                       (by default, the file is assumed to be the same one\n");
    printf("                       provided with the -k option.)\n");
    printf("   -Z                = ZAP (remove) all signature segments.\n");
    printf("options:\n");
    printf("    -n      --- ask for a chain-of-custody note.\n");
    printf("    -v      --- Just print the version number and exit.\n");
    exit(0);
}


int afsign(const char *fn)
{
    AFFILE *af = af_open(fn,O_RDWR,0);
    if(!af) af_err(1,"%s",fn);

    struct af_vnode_info vni;
    if(af_vstat(af,&vni)) err(1,"af_vstat");

    if(vni.supports_metadata==0){
	/* If it is a raw file, we can create an AFM file to sign */
	if(vni.is_raw==0) errx(1,"%s: file does not support metadata. Cannot sign\n",fn);
	af_close(af);			// afm will open it
	char afmfile[MAXPATHLEN+1];
	char file000[MAXPATHLEN+1];
	char extension[MAXPATHLEN+1];
	strcpy(afmfile,fn);
	char *period = strrchr(afmfile,'.');
	if(!period) errx(1,"%s: file does not support metadata and lacks a file extension,\n"
			 "which is needed to create an AFM file '%s\n",afmfile,fn);
	strcpy(extension,period+1);	// get the extension

	/* If the file being opened is not a .000 file, and a .000 file exists, do not proceed */
	strcpy(period,".000");
	strcpy(file000,afmfile);	// make the 000 file
	strcpy(period,".afm");
	
	if(strcmp(extension,"000")!=0){
	    if(access(file000,F_OK)==0){
		errx(1,"Can't create .afm file because %s exists.\n",file000);
	    }
	}
	
	strcpy(period,".afm");		// we are now going to make an afm file
	af = af_open(afmfile,O_RDWR|O_CREAT,0600);
	if(!af) af_err(1,"%s: file does not support metadata and cannot create AFM file '%s\n",fn,afmfile);
	if(strcmp(extension,"000")!=0){
	    af_update_seg(af,AF_RAW_IMAGE_FILE_EXTENSION,0,(const u_char *)extension,strlen(extension));
	    af_close(af);
	    unlink(file000);		// get rid of that .000 file
	    af = af_open(afmfile,O_RDWR,0600);
	    if(!af) af_err(1,"%s: Created AFM file but cannot re-open it\n",fn);
	    /* Read the first byte to force a call to afm_split_raw_setup().
	     * The results of the read don't matter, but we better be able to read.
	     */
	    u_char buf[1];
	    if(af_read(af,buf,1)!=1){
		err(1,"Cannot read first byte of %s",fn);
	    }
	    af_seek(af,0L,0);
	}
    }

    seglist segments(af);

    if(isatty(fileno(stdout))){
	printf("Signing segments...\n");
	fflush(stdout);
    }
    
    bool signed_unsigned_segments = false;
    if(segments.has_signed_segments()==false){
	if(af_set_sign_files(af,opt_sign_key_file,opt_sign_cert_file)){
	    errx(1,"key file '%s' or certificate file '%s' is invalid",
		 opt_sign_key_file,opt_sign_cert_file);
	}
	int r = af_sign_all_unsigned_segments(af);
	if(r<0) af_err(1,"%s: all unsigned segments cannot be signed.",fn);
	if(r>0) signed_unsigned_segments = true;
    }

    aff_bom bom(opt_note);
    if(bom.read_files(opt_sign_cert_file,opt_sign_key_file)) err(1,"Can't read signature files???");

    u_char *pagebuf = (unsigned char *)calloc(af_page_size(af),1);
    u_char *parity_buf = (unsigned char *)calloc(af_page_size(af),1);
    bool compute_parity = true;		// do we need to compute the parity?

    /* Create the parity buffer if it doesn't exist. If the parity buffer exists, we'll just trust it.
     * We could do a two-pass here, one for creating the parity buffer, another for creating the BOM.
     * But that would require reading the data twice; hence this extra layer of complexity.
     */
    size_t parity_buf_len = af_page_size(af);
    if(af_get_seg(af,AF_PARITY0,0,parity_buf,&parity_buf_len)==0){
	compute_parity = false;		// no need to compute it; we read it
    }

    for(seglist::const_iterator seg = segments.begin(); seg!= segments.end();seg++){
	const char *segname = seg->name.c_str();

	if(isatty(fileno(stdout))){
	    printf("\rCalculating BOM for segment %s...   ",segname);
	    printf("\n");
	    fflush(stdout);
	}

	u_char seghash[32]; /* resultant message digest; could be any size */
	unsigned int seghash_len = sizeof(seghash); /* big enough to hold SHA256 */
	int sigmode = 0;
	int64_t pagenumber = af_segname_page_number(segname);
	if(pagenumber>=0){
	    /* Page segments must run in SIGNATURE_MODE1 - the actual data in the page */
	    size_t this_pagesize = af_page_size(af);
	    if(af_get_page(af,pagenumber,pagebuf,&this_pagesize)){ 
		free(pagebuf);
		return -1;
	    }
	    /* Add to parity buf if we are making a parity page*/
	    if(compute_parity){
		for(u_int i=0;i<this_pagesize;i++){
		    parity_buf[i] ^= pagebuf[i];
		}
	    }
	    aff_bom::make_hash(seghash,0,segname,pagebuf,this_pagesize);
	    sigmode = AF_SIGNATURE_MODE1;
	}
	else{
	    /* Non-Page segments can be run in SIGNATURE_MODE0 - the actual data in the file */
	    size_t seglen=0;
	    if(af_get_seg(af,segname,0,0,&seglen)){
		err(1,"Cannot read length of segment '%s' on input file %s", segname,af_filename(af));
	    }
	    unsigned char *segbuf = (unsigned char *)malloc(seglen);
	    if(!segbuf){
		err(1,"Cannot allocated %d bytes for segment '%s' in %s",
		    (int)seglen,segname,af_filename(af));
	    }
	    /* Now get the raw source segment */
	    uint32_t arg=0;
	    if(af_get_seg(af,segname,&arg,segbuf,&seglen)){
		err(1,"Cannot read segment '%s' in %s. Deleteing output file", segname,af_filename(af));
	    }
	    aff_bom::make_hash(seghash,arg,segname,segbuf,seglen);
	    sigmode = AF_SIGNATURE_MODE0;
	    free(segbuf);
	}
	bom.add(segname,sigmode,seghash,seghash_len); // add to the BOM
    }

    /* If we have been making the parity buf:
     * 1 - Write it out; add it to the BOM
     * 2 - Write out the signature segment for the parity buf; add it to the bom
     */
    if(compute_parity){
	if(af_update_seg(af,AF_PARITY0,0,parity_buf,af_page_size(af))) err(1,"Can't write %s",AF_PARITY0);

	/* Add the parity page that we made to the BOM */
	u_char seghash[32]; /* resultant message digest; could be any size */
	unsigned int seghash_len = sizeof(seghash); /* big enough to hold SHA256 */

	aff_bom::make_hash(seghash,0,AF_PARITY0,parity_buf,af_page_size(af));
	bom.add(AF_PARITY0,AF_SIGNATURE_MODE0,seghash,seghash_len);


	/* If we are signing segments for the first time, we need to sign the parity page
	 * and then add the parity page's signature segment to the BOM as well.
	 */
	if(signed_unsigned_segments){
	    af_sign_seg(af,AF_PARITY0);	// sign the parity segment if we signed the other segments
	    bom.add(af,AF_PARITY0_SIG);

	    u_char buf[1024];
	    size_t buflen = sizeof(buf);

	    const char *segname = AF_PARITY0_SIG;
	    if(af_get_seg(af,segname,0,buf,&buflen)==0){ // Get the signature 
		aff_bom::make_hash(seghash,0,segname,buf,buflen); // and add it to the BOM
		bom.add(segname,AF_SIGNATURE_MODE0,seghash,seghash_len);
	    }
	}
    }

    if(isatty(fileno(stdout))){
	printf("                                                    \r\n");
	fflush(stdout);
    }
    
    bom.close();
    bom.write(af,segments);
    af_close(af);
    return 0;
}

int remove_signatures(const char *fn)
{
    AFFILE *af = af_open(fn,O_RDWR,0);
    if(!af) af_err(1,"%s",fn);
    
    aff::seglist sl(af);
    for(aff::seglist::const_iterator i = sl.begin();
	i!= sl.end();
	i++){
	if(af_is_signature_segment(i->name.c_str()) || i->name==AF_SIGN256_CERT){
	    cout << "Deleting " << i->name << "\n";
	    af_del_seg(af,i->name.c_str());
	}
    }
    af_close(af);
    return 0;
}

int main(int argc,char **argv)
{
    int bflag, ch;
    int opt_zap = 0;

    bflag = 0;
    while ((ch = getopt(argc, argv, "nk:c:h?vZ")) != -1) {
	switch (ch) {
	case 'n': opt_note = 1;break;
	case 'k':
	    if(access(optarg,R_OK)) err(1,"%s",optarg);
	    opt_sign_key_file = optarg;
	    break;
	case 'c':
	    if(access(optarg,R_OK)) err(1,"%s",optarg);
	    opt_sign_cert_file = optarg;
	    break;
	case 'v':
	    printf("%s version %s\n",progname,PACKAGE_VERSION);
	    exit(0);
	case 'Z':
	    opt_zap = 1;
	    break;
	case 'h':
	case '?':
	default:
	    usage();
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if(opt_sign_cert_file==0) opt_sign_cert_file=opt_sign_key_file; // if not set, make same as key file


    if(argc!=1){
	usage();
    }

    if(opt_zap) return remove_signatures(argv[0]);

    /* We either need both a key file and a cert file, or neither */
    if((opt_sign_key_file==0) || (opt_sign_cert_file==0)){
	errx(1,"Both a private key and a certificate must be specified.");
    }


    return afsign(argv[0]);
}
#else
int main(int argc,char **argv)
{
    fprintf(stderr,"afflib compiled without USE_AFFSIGS.  afsign cannot run.\n");
    exit(-1);
}

#endif

