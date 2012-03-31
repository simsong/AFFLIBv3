#include "qemu-common.h"
#include "block_int.h"

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"


int main(int argc,char **argv)
{
    BlockDriverState *bs;
    BlockDriver *drv=NULL;
    char fmt_name[128], size_buf[128], dsize_buf[128];
    uint64_t total_sectors=0;
    //BlockDriverInfo bdi;
    int sector_start = atoi(argv[2]);
    int sector_count = atoi(argv[3]);

    unsigned char *buf = malloc(sector_count*512);
    printf("start: %d count: %d\n",sector_start,sector_count);

    bdrv_init();

    bs = bdrv_new("");
    if(!bs) errx(1,"not enough memory for qemu");

    if(bdrv_open2(bs,argv[1],0,drv) < 0){
	errx(1,"Could not open %s\n",argv[1]);
    }
    bdrv_get_format(bs, fmt_name, sizeof(fmt_name));
    bdrv_get_geometry(bs, &total_sectors);
    printf("image: %s  format: %s  size: %"PRId64" bytes\n",argv[1],fmt_name,total_sectors);

    if(bdrv_read(bs,sector_start,buf,sector_count)<0){
	errx(1,"Can't read");
    }
    write(fileno(stdout),buf,sector_count*512);

    return(0);

    
}

