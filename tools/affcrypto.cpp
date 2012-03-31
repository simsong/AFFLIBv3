/*
 * afcrypto.cpp:
 *
 * command for dealing with encryption issues
 */

/* Public Domain Software 
 * Simson L. Garfinkel
 * Naval Postgraduate School
 *
 * The software provided here is released by the Naval Postgraduate
 * School, an agency of the U.S. Department of Navy.  The software bears
 * no warranty, either expressed or implied. NPS does not assume legal
 * liability nor responsibility for a User's use of the software or the
 * results of such use.
 *
 * Please note that within the United States, copyright protection, under
 * Section 105 of the United States Code, Title 17, is not available for
 * any work of the United States Government and/or for any works created
 * by United States Government employees. 
 */



#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"
#include "utils.h"

#include <stdio.h>
#include <algorithm>
#include <vector>

const char *progname = "afcrypto";
#define DEFAULT_PASSPHRASE_FILE ".affpassphrase"
int opt_debug = 0;
int opt_verbose = 0;
int opt_just_print_encrypted_count = 0;
int opt_just_print_unencrypted_count = 0;
char *opt_unsealing_private_key_file= 0;
int opt_xml = 0;

void change_passphrase(const char *fn,const char *old_passphrase,const char *new_passphrase)
{
    int fail = 0;

    AFFILE *af = af_open(fn,O_RDWR,0666);
    if(!af) af_err(1,fn);
    if(af_change_aes_passphrase(af,old_passphrase,new_passphrase)){
	warnx("%s: af_change_aes_passphrase failed",fn);
	fail = 1;
    }
    af_close(af);
    if(!fail) printf("%s: passphrase changed.\n",fn);
}

void get_and_change_passphrase(const char *fn)
{
    char old_passphrase[1024];
    char new_passphrase[1024];

    memset(old_passphrase,0,sizeof(old_passphrase));
    memset(new_passphrase,0,sizeof(new_passphrase));

    printf("Enter old passphrase: ");
    if(fgets(old_passphrase,sizeof(old_passphrase),stdin)==0) return;
    char *cc = strchr(old_passphrase,'\n');if(cc) *cc='\000';

    /* See if this passphrase works*/

    AFFILE *af = af_open(fn,O_RDONLY,0666);
    if(!af) af_err(1,fn);
    if(af_use_aes_passphrase(af,old_passphrase)){
	errx(1,"passphrase incorrect");
    }
    af_close(af);

    printf("Enter new passphrase: ");
    if(fgets(new_passphrase,sizeof(new_passphrase),stdin)==0) return;
    cc = strchr(new_passphrase,'\n');if(cc) *cc='\000';
    change_passphrase(fn,old_passphrase,new_passphrase);
}

void usage()
{
    printf("afcrypto version %s\n",PACKAGE_VERSION);
    printf("usage: afcrypto [options] filename.aff [filename2.aff ... ]\n");
    printf("   prints if each file is encrypted or not.\n");
    printf("options:\n");
    printf("    -x      --- output in XML\n");
    printf("    -j      --- Just print the number of encrypted segments\n");
    printf("    -J      --- Just print the number of unencrypted segments\n");

    printf("\nData conversion options:\n");
    printf("    -e      --- encrypt the unencrypted non-signature segments\n");
    printf("    -d      --- decrypt the encrypted non-signature segments\n");
    printf("    -r      --- change passphrase (take old and new from stdin)\n");
    printf("    -O old  --- specify old passphrase\n");
    printf("    -N new  --- specify new passphrase\n");
    printf("    -K mykey.key  -- specifies a private keyfile for unsealing (may not be repeated)\n");
    printf("    -C mycert.crt -- specifies a certificate file for sealing (may be repeated)\n");
    printf("    -S      --- add symmetric encryptiong (passphrase) to AFFILE encrypted with public key\n");
    printf("                    (requires a private key and a specified passphrase).\n");
    printf("    -A      --- add asymmetric encryption to a AFFILE encrypted with a passphrase\n");
    printf("                    (requires a certificate file spcified with the -C option\n");
    

    printf("\nPassword Cracking Options:\n");
    printf("    -p passphrase --- checks to see if passphrase is the passphrase of the file\n");
    printf("                exit code is 0 if it is, -1 if it is not\n");
    printf("    -k      --- attempt to crack passwords by reading a list of passwords from ~/.affpassphrase\n");
    printf("    -f file --- Crack passwords but read them from file.\n");

    printf("\nDebugging:\n");
    printf("    -V      --- Just print the version number and exit.\n");
    printf("    -D      --- debug; print out each key as it is tried\n");
    printf("    -l      --- List the installed hash and encryption algorithms \n");
    printf("Note: This program ignores the environment variables:\n");
    puts(AFFLIB_PASSPHRASE);
    puts(AFFLIB_PASSPHRASE_FILE);
    puts(AFFLIB_PASSPHRASE_FD);
    puts(AFFLIB_DECRYPTING_PRIVATE_KEYFILE);
    exit(0);
}

/* Try each of the passphrases in the file against the passphrase. If it is found, return it. */
char  *check_file(AFFILE *af,const char *passphrase_file)
{
    char *ret = 0;
    FILE *f = fopen(passphrase_file,"r");
    if(!f) return 0;

    char buf[1024];
    memset(buf,0,sizeof(buf));
    while(fgets(buf,sizeof(buf)-1,f)){
	char *cc = strchr(buf,'\n');
	if(cc) *cc = 0;
	if(opt_debug){
	    if(opt_debug) printf("checking with '%s' ... ",buf);
	    fflush(stdout);
	}
	int r= af_use_aes_passphrase(af,buf);
	if(r==0){
	    if(opt_debug) printf("YES!\n");
	    ret = strdup(buf);
	    break;
	}
    }
    fclose(f);
    return ret;
}

/**
 * This will eventually decrypt non-signature segments that are
 * encrypted
 *
 * @param af - the AFFILE to open
 * @param count - The number of pages actually encrypted
 */
int af_decrypt_encrypted_segments(AFFILE *af, int *count, int mode)
{
    af_set_option(af,AF_OPTION_AUTO_ENCRYPT,0);
    af_set_option(af,AF_OPTION_AUTO_DECRYPT,0); // turn off auto decryption
    aff::seglist sl(af);	       // get the list of the segments
    af_set_option(af,AF_OPTION_AUTO_DECRYPT,1); // turn auto decryption back on
    for(aff::seglist::const_iterator si = sl.begin();si!=sl.end();si++){
	if(opt_debug) printf(" checking segment %s",si->name.c_str());
	if(af_is_encrypted_segment(si->name.c_str())){

	    if(mode == O_RDONLY){	// if readonly, just tally
		(*count) ++;
		if(opt_debug) printf("  would decrypt segment\n");
		continue;
	    }

	    /* Generate the name of the unencrypted segment */
	    char segname[AF_MAX_NAME_LEN];
	    strcpy(segname,si->name.c_str());
	    char *cc = strstr(segname,AF_AES256_SUFFIX);
	    if(!cc){
		if(opt_debug) printf(" will not decrypt AFFKEY segments; will be deleted later.\n");
		continue;		// something is wrong; can't find the /aes256
	    }
	    *cc = '\000';		// truncate off the /aes256

	    /* Get the segment and put it, which will force the decryption to take place */
	    if(opt_debug) printf("  decrypting segment\n");
	    u_char *buf = (u_char *)malloc(si->len);
	    if(!buf) warn("malloc(%zd) failed", si->len);
	    else {
		uint32_t arg;
		size_t datalen = si->len;
		if(af_get_seg(af,segname,&arg,buf,&datalen)){
		    warn("Could not read segment '%s'",segname);
		}
		else{
		    /* si->datalen >= datalen.
		     * si->datalen is the length of the encrypted segment.
		     * datalen is the length of the decrypted segment.
		     */
		    assert(si->len >= datalen);
		    assert(si->arg==arg);
		    if(af_update_seg(af,segname,arg,buf,datalen)){
			warn("Could not decrypt segment '%s'",si->name.c_str());
		    } else {
			(*count) ++;
		    }
		}
		free(buf);
	    }
	} else {
	    if(opt_debug) printf("  not encrypted\n");
	}
    }
    /* Delete the AF_AFFKEY segment */
    if(af_get_seg(af,AF_AFFKEY,0,0,0)==0) af_del_seg(af,AF_AFFKEY);
    /* Delete all of the EVP segments */
    for(int i=0;;i++){
	char segname[1024];
	snprintf(segname,sizeof(segname),AF_AFFKEY_EVP,i);
	if(af_get_seg(af,segname,0,0,0)!=0) break; // found the last segment
	if(af_del_seg(af,segname)) warn("Cannot delete segment %s",segname);
    }
    return 0;
}


/**
 * Encrypts the non-signature segments that are not encrypted.
 * There is no reason to encrypt the signature segments.
 *
 * @param af - the AFFILE to open
 * @param count - The number of pages actually encrypted
 */

int af_encrypt_unencrypted_nonsignature_segments(AFFILE *af,int *count,int mode)
{
    af_set_option(af,AF_OPTION_AUTO_DECRYPT,0);	// do not automatically decrypt
    aff::seglist sl(af);
    for(aff::seglist::const_iterator si = sl.begin();si!=sl.end();si++){
	if(si->name == AF_AFFKEY) continue; // don't encrypt the affkey!
	if(strstr(si->name.c_str(),"affkey_evp")) continue;
	if(!af_is_encrypted_segment(si->name.c_str()) &&
	   !af_is_signature_segment(si->name.c_str())){

	    if(mode == O_RDONLY){	// if readonly, just tally
		(*count) ++;
		continue;
	    }

	    /* Get the segment and put it, which will force the encryption to take place */
	    if(opt_debug) printf("  encrypting segment %s\n",si->name.c_str());
	    u_char *buf = (u_char *)malloc(si->len);
	    if(!buf) warn("Cannot encrypt segment '%s' --- too large (%zd bytes) --- malloc failed",
			  si->name.c_str(),si->len);
	    else {
		uint32_t arg;
		size_t datalen = si->len;
		if(af_get_seg(af,si->name.c_str(),&arg,buf,&datalen)){
		    warn("Could not read segment '%s'",si->name.c_str());
		}
		else{
		    /* make sure that what we read is what we thought we were going to read */
		    assert(si->len==datalen);
		    assert(si->arg==arg);
		    if(af_update_seg(af,si->name.c_str(),arg,buf,datalen)){
			warn("Could not encrypt segment '%s'",si->name.c_str());
		    } else {
			(*count) ++;
		    }
		}
		free(buf);
	    }
	} else {
	    if(opt_debug) printf("  already encrypted or signed: %s\n",si->name.c_str());
	}
    }
    af_set_option(af,AF_OPTION_AUTO_DECRYPT,1);	// go back to automatically decrypting
    return 0;
}

void list_openssl_hashes()
{
    const char *digests[] = {"md5","sha1","sha256",0};
    OpenSSL_add_all_algorithms();
    for(int i=0;digests[i];i++){
	printf("OpenSSL has %s: %s\n",digests[i],EVP_get_digestbyname(digests[i]) ? "YES" : "NO");
    }
    exit(0);
}

int main(int argc,char **argv)
{
    int ch;
    const char *old_passphrase=0;
    const char *new_passphrase=0;
    const char *check_passphrase = 0;
    char *passphrase_file = 0;
    const char *progname = argv[0];
    int opt_encrypt = 0;
    int opt_decrypt = 0;
    int opt_add_passphrase_to_public_key = 0;
    int opt_add_public_key_to_passphrase = 0;
    
    int mode = O_RDONLY;		// mode for opening AFF file
    const char **certificates = (const char **)malloc(0);
    int num_certificates = 0;
    const char *envvars[] = {AFFLIB_PASSPHRASE,AFFLIB_PASSPHRASE_FILE,AFFLIB_PASSPHRASE_FD,
		      AFFLIB_DECRYPTING_PRIVATE_KEYFILE,0};
    for(int i=0;envvars[i];i++){
    /* Don't use auto-supplied passphrases */
#ifdef HAVE_UNSETENV
	unsetenv(envvars[i]);
#else
	if(getenv(envvars[i])){
	    fprintf(stderr,"Please unset %s and restart\n",envvars[i]);
	    exit(1);
	}
#endif
    }
    
    int opt_change = 0;
    const char *home = getenv("HOME");

    while ((ch = getopt(argc, argv, "zreC:SAO:N:p:f:kdDh?VK:vljJx:")) != -1) {
	switch (ch) {
	case 'x': opt_xml = 1; break;
	case 'j': opt_just_print_encrypted_count =1;break;
	case 'J': opt_just_print_unencrypted_count =1;break;

	    /* These options make the mode read-write */
	case 'r': opt_change = 1;  mode = O_RDWR; break;
	case 'e': opt_encrypt = 1; mode = O_RDWR; break;
	case 'd': opt_decrypt = 1; mode = O_RDWR; break;
	case 'S': opt_add_passphrase_to_public_key = 1; mode = O_RDWR; break;
	case 'A': opt_add_public_key_to_passphrase = 1; mode = O_RDWR; break;
	    /* These just set up variables */
	case 'C': 
	    certificates = (const char **)realloc(certificates,sizeof(int *)*(num_certificates+1));
	    certificates[num_certificates] = optarg;
	    num_certificates++;
	    break;
	case 'K': opt_unsealing_private_key_file = optarg;break;
	case 'O': old_passphrase = optarg;break;
	case 'N': new_passphrase = optarg;break;
	case 'p': check_passphrase = optarg;break;
	case 'f': passphrase_file = optarg;break;
	case 'k': 
	    if(!home) home = "/";
	    passphrase_file = (char *)malloc(strlen(home)+strlen(DEFAULT_PASSPHRASE_FILE)+2);
	    strcpy(passphrase_file,home);
	    strcat(passphrase_file,"/");
	    strcat(passphrase_file,DEFAULT_PASSPHRASE_FILE);
	    break;
	case 'D': opt_debug = 1;break;
	case 'v': opt_verbose = 1;break;
	case 'l': list_openssl_hashes(); exit(0);
	case 'h':
	case '?':
	default:
	    usage();
	    break;
	case 'V':
	    printf("%s version %s\n",progname,PACKAGE_VERSION);
	    exit(0);
	}
    }
    argc -= optind;
    argv += optind;
    if(argc<1){
	fprintf(stderr,"No image file specified\n");
	usage();
    }

    if(opt_just_print_encrypted_count && opt_just_print_unencrypted_count){
	errx(1,"Options -j and -J conflict\n");
    }

    if(num_certificates>0 && (opt_encrypt==0 && opt_decrypt==0 && opt_add_public_key_to_passphrase==0)){
	errx(1,"Encryption certificates specified but neither -e nor -d option not set. "
	     "What do you want me to do with these certificates? ");
    }
	    
    if((check_passphrase || passphrase_file) && opt_encrypt){
	err(1,"Sorry, can't both encrypt and password crack. Pick one.\n");
    }

    if(opt_encrypt && (new_passphrase==0 && num_certificates==0) && mode!=O_RDONLY){
	err(1,"Currently -e requires that the passphrase be specified on the command line\n"
	    "or that one or more encryption certificates be provided\n");
    }

    while(argc--){
	const char *fname = *argv++;

	if(opt_change){
	    if(old_passphrase && new_passphrase) change_passphrase(fname,old_passphrase,new_passphrase);
	    else get_and_change_passphrase(fname);
	}

	/* Get the information */
	AFFILE *af = af_open(fname,mode,0);
	if(!af) af_err(1,"af_open(%s)",fname);
	if(af_identify(af)!=AF_IDENTIFY_AFF && af_identify(af)!=AF_IDENTIFY_AFD){
	    errx(1,"Cannot encrypt %s: %s only supports AFF and AFD files.",af_filename(af),progname);
	}

	if(opt_encrypt && new_passphrase){
	    int r = af_establish_aes_passphrase(af,new_passphrase);
	    switch(r){
	    case AF_ERROR_NO_AES: errx(1,"AFFLIB: AES256 not available; cannot continue");
	    case AF_ERROR_NO_SHA256: errx(1,"AFFLIB: SHA256 not available; cannot continue");
	    default: err(1,"%s: cannot establish passphrase (error %d)",fname,r);
	    case 0: 
	    case AF_ERROR_AFFKEY_EXISTS:
		/* no matter if we established it or if a phrase already exists, try to use it now */
		/* File already has a passphrase; see if this is it. */
		break;
	    }
	    r = af_use_aes_passphrase(af,new_passphrase);
	    switch(r){
	    case 0: break;		// everything okay
	    case AF_ERROR_WRONG_PASSPHRASE: errx(1,"%s: wrong passphrase",fname);
	    default: errx(1,"%s: passphrase already established (error %d)",fname,r);
	    }
        }

	if(opt_decrypt && !old_passphrase && getenv(AFFLIB_PASSPHRASE)){
	    old_passphrase = getenv(AFFLIB_PASSPHRASE);
	}
	if(opt_decrypt && old_passphrase){
	    int r = af_use_aes_passphrase(af, old_passphrase);
	    switch(r){
	    case 0: printf("Passphrase is good!\n"); break;
	    case AF_ERROR_WRONG_PASSPHRASE: errx(1,"%s: wrong passphrase",fname);
	    }
	}

	if (opt_add_public_key_to_passphrase){ 
	  if(!num_certificates) errx(1,"You must specify a certificate with the -C option");
	  if(!check_passphrase) errx(1,"You must specify a passphrase with the -p option");
	  printf("Attepmting to add public key to AFFILE...\n");
	  if(af->crypto->sealing_key_set) return AF_ERROR_KEY_SET;		// already enabled
	  unsigned char affkey[32];
	  int r = af_get_aes_key_from_passphrase(af,check_passphrase,affkey);
	  if(r) errx(1, "%s: cannot get aes key.  Failed to add Public Key", fname);
	  af_seal_affkey_using_certificates(af, certificates, num_certificates, affkey);
	  printf("...Public key added successfully.\n");
	}

	if(opt_encrypt && num_certificates){
	    if(af_set_seal_certificates(af,certificates,num_certificates)){
		errx(1,"%s: can't set encryption certificate%s",fname,num_certificates==1 ? "" : "s");
	    }
	}
	if(opt_encrypt){
	    int count = 0;
	    if(af_encrypt_unencrypted_nonsignature_segments(af,&count,mode)){
		errx(1,"%s: can't encrypt unsigned, unencrypted segments",fname);
	    }
	    if(mode==O_RDONLY){		// if it is readonly just print the number of segments that would be changed.
		printf("%d\n",count);
		af_close(af);
		continue;
	    }
	}
	if(opt_decrypt){
	    int count = 0;
	    if(af_decrypt_encrypted_segments(af, &count, mode)){
	    }
	    if(mode==O_RDONLY){
		printf("%d\n",count);
		af_close(af);
		continue;
	    }
	}

	if(opt_add_passphrase_to_public_key) {
	    if(!new_passphrase) errx(1,"You must specify a new passphrase with the -N option");
	    printf("Attempting to add passphrase...\n");
	    u_char affkey[32];
	    if(af_get_affkey_using_keyfile(af, opt_unsealing_private_key_file,affkey)){
		errx(1,"%s: cannot unseal AFFKEY",fname);
	    }
	    if(af_save_aes_key_with_passphrase(af,new_passphrase,affkey)){
		af_err(1,"%s: could not set the passphrase",fname);
	    }
	    printf("... new passphrase established.\n");
	}


	af_vnode_info vni;
	memset(&vni,0,sizeof(vni));
	if(af_vstat(af,&vni)) err(1,"%s: af_vstat failed: ",fname);
	const char *the_passphrase = 0;	// the correct passphrase

	if(opt_just_print_encrypted_count){
	    printf("%d\n",vni.segment_count_encrypted);
	    af_close(af);
	    continue;
	}

	if(opt_just_print_unencrypted_count){
	    printf("%d\n",vni.segment_count_total-vni.segment_count_encrypted);
	    af_close(af);
	    continue;
	}


	/* were we supposed to try a check_passphrase? */
	if(check_passphrase){
	    if(af_use_aes_passphrase(af,check_passphrase)==0){
		the_passphrase = check_passphrase;
	    }
	    af_use_aes_passphrase(af,0); // clear the passphrase
	}

	/* Is a passphrase file provided? */
	if(!the_passphrase && passphrase_file){
	    the_passphrase = check_file(af,passphrase_file);
	    if(the_passphrase){
		af_use_aes_passphrase(af,0); // clear the passphrase
	    }
	}
	
	if(opt_xml){
	    /* This should be replaced with our xml.cpp object */
	    printf("<afcrypto>\n");
	    printf("  <image_filename>%s</image_filename>\n",fname);
	    printf("  <segment_count_total>%d</segment_count_total>\n",vni.segment_count_total);
	    printf("  <segment_count_signed>%d</segment_count_signed>\n",vni.segment_count_signed);
	    printf("  <segment_count_encrypted>%d</segment_count_encrypted>\n",vni.segment_count_encrypted);
	    printf("  <page_count_total>%d</page_count_total>\n",vni.page_count_total);
	    printf("  <page_count_encrypted>%d</page_count_encrypted>\n",vni.page_count_encrypted);
	    if(the_passphrase){
		printf("  <passphrase correct='1'>%s</passphrase>\n",the_passphrase);
	    }
	    printf("</afcrypto>\n");
	}
	else{
	    /* re-run vstat because counts may have changed */
	    if(af_vstat(af,&vni)) err(1,"%s: af_vstat failed: ",fname);
	    printf("%s: %5d segments; %5d signed; %5d encrypted; %5d pages; %5d encrypted pages",
		   fname,vni.segment_count_total,vni.segment_count_signed,vni.segment_count_encrypted,
		   vni.page_count_total,vni.page_count_encrypted );
	    if(the_passphrase) printf("passphrase correct (\"%s\")",the_passphrase);
	    putchar('\n');
	}
	af_close(af);
    }
    return(0);
}
