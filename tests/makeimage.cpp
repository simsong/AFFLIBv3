/*
 * makeimage.cpp:
 * 
 * Make an image with a given number of sectors.
 * This file is a work of a US government employee and as such is in the Public domain.
 * Simson L. Garfinkel, March 12, 2012
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

const char *progname = "makeimage";

void usage()
{
    errx(1,"usage: %s file blockcount\n",progname);
}

int main(int argc,char **argv)
{
    if(argc!=3) usage();

    int  count = atoi(argv[2]);
    char buf[512];

    FILE *out = fopen(argv[1],"wb");
    if(!out) err(1,"fopen(%s)",argv[1]);

    memset(buf,' ',sizeof(buf));
    buf[511] = '\000';
    for(int i=0;i<count;i++){
	sprintf(buf,"Block %d\n",i);
	fwrite(buf,sizeof(buf),1,out);
    }
    fclose(out);
}
