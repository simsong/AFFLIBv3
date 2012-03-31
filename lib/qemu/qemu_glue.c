#include "qemu-common.h"
#include "block_int.h"

#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"


void *get_mmap_addr(unsigned long size)
{
    return NULL;
}

void qemu_free(void *ptr)
{
    free(ptr);
}

void *qemu_malloc(size_t size)
{
    return malloc(size);
}

void *qemu_mallocz(size_t size)
{
    void *ptr;
    ptr = qemu_malloc(size);
    if (!ptr)
        return NULL;
    memset(ptr, 0, size);
    return ptr;
}

char *qemu_strdup(const char *str)
{
    char *ptr;
    ptr = qemu_malloc(strlen(str) + 1);
    if (!ptr)
        return NULL;
    strcpy(ptr, str);
    return ptr;
}

void term_printf(const char *str)
{
    puts(str);
}

void term_print_filename(const char *filename)
{
    puts(filename);
}

void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

/* strcat and truncate. */
char *pstrcat(char *buf, int buf_size, const char *s)
{
    int len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}



int strstart(const char *str, const char *val, const char **ptr)
{
    const char *p, *q;
    p = str;
    q = val;
    while (*q != '\0') {
        if (*p != *q)
            return 0;
        p++;
        q++;
    }
    if (ptr)
        *ptr = p;
    return 1;
}



