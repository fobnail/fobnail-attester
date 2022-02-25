#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

#include <fobnail-attester/meta.h>

static const char *bad_index = "<BAD INDEX>";

static int att_read(int fd, uint8_t *buf, size_t count, const char *prefix)
{
    ssize_t r = 1;
    size_t r2 = 0;

    while (r2 != count && r != 0) {
        r = read(fd, buf + r2, count - r2);
        if (r == -1) {
            if (errno != EINTR) {
                perror(prefix);
                return -1;
            }
        } else {
            r2 += r;
        }
    }

    if (r2 != count) {
        fprintf(stderr, "%s: Unexpected end of file\n", prefix);
        return -1;
    }

    return 0;
}

static void *read_file(off_t base, size_t *max_len, const char *filename)
{
    struct stat statbuf;
    int fd;
    uint8_t *p;

    /*
     * Don't print error message on missing file, as we will try to read
     * files that may or may not be present.
     */
    if ((fd = open(filename, O_RDONLY)) == -1) {
        if (errno != ENOENT)
            perror(filename);

        return NULL;
    }

    /*
     * Check file size, don't allocate more than can be read.
     */
    if (fstat(fd, &statbuf) == 0) {
        if (base >= statbuf.st_size) {
            fprintf(stderr, "%s: Can't read data beyond EOF\n",
                filename);
            p = NULL;
            goto out;
        }
        if (*max_len > (size_t)statbuf.st_size - base)
            *max_len = statbuf.st_size - base;
    }

    if ((p = malloc(*max_len)) == NULL) {
        perror("malloc");
        goto out;
    }

    if (lseek(fd, base, SEEK_SET) == -1) {
        fprintf(stderr, "%s: ", filename);
        perror("lseek");
        goto err_free;
    }

    if (att_read(fd, p, *max_len, filename) == 0)
        goto out;

err_free:
    free(p);
    p = NULL;

out:
    if (close(fd) == -1)
        perror(filename);

    return p;
}

static void ascii_filter(char *bp, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        if (!isprint(bp[i]))
            bp[i] = '.';
}

static char *_dmi_string(const struct dmi_header *dm, uint8_t s, int filter)
{
    char *bp = (char *)dm->data;

    bp += dm->length;
    while (s > 1 && *bp) {
        bp += strlen(bp);
        bp++;
        s--;
    }

    if (!*bp)
        return NULL;

    if (filter)
        ascii_filter(bp, strlen(bp));

    return bp;
}

const char *dmi_string(const struct dmi_header *dm, uint8_t s)
{
    char *bp;

    if (s == 0)
        return "Not Specified";

    bp = _dmi_string(dm, s, 1);
    if (bp == NULL)
          return bad_index;

    return bp;
}

static inline void free_null_ptr(void *ptr)
{
    if (ptr != NULL) {
        free(ptr);
        ptr = NULL;
    }
}

static int dmi_info_to_meta(struct dmi_header *h, struct meta_data *meta)
{
    const char *sn, *pn, *mfr;

    if (h->length < 0x08)
        return -1;

    mfr = dmi_string(h, h->data[MRF_OFFSET]);
    pn  = dmi_string(h, h->data[PN_OFFSET]);
    sn  = dmi_string(h, h->data[SN_OFFSET]);

    meta->manufacturer   = malloc(strlen(mfr) + 1);
    meta->product_name   = malloc(strlen(pn) + 1);
    meta->serial_number  = malloc(strlen(sn) + 1);
    if (!meta->manufacturer || !meta->product_name || !meta->serial_number) {
        fprintf(stderr, "Cannot allocate memory.\n");
        return -1;
    }
    strcpy(meta->manufacturer, mfr);
    strcpy(meta->product_name, pn);
    strcpy(meta->serial_number, sn);

    printf("Manufacturer >%s<\n", meta->manufacturer);
    printf("Product Name >%s<\n", meta->product_name);
    printf("Serial Number >%s<\n", meta->serial_number);

    return 0;
}

static int att_smbios_decode(uint8_t *buf, const char *devmem, struct meta_data *meta)
{
    size_t len;
    uint8_t *dmi_buf = NULL;
    union sm_t *sm = (union sm_t *)buf;

    if (memcmp(sm->sm2.anchor, "_SM_", sizeof(sm->sm2.anchor)) == 0) {
        printf("SMBIOSv2\n");
        len = sm->sm2.len;
        // TODO: calculate checksums
        fprintf(stderr, "Currently SMBIOSv2 is not supported yet.\n");
        //I don't have SMBIOSv2 devices and cannot check and test it, returns -1
        return -1;
    } else if (memcmp(sm->sm3.anchor, "_SM3_", sizeof(sm->sm3.anchor)) == 0) {
        uint8_t *p;
        struct dmi_header *hdr;

        printf("SMBIOSv3: len = %d\n", sm->sm3.len);
        len = sm->sm3.len;
        // TODO: calculate checksum

        dmi_buf = read_file(0, &len, devmem);
        if (dmi_buf == NULL)
            return -1;

        hdr = (struct dmi_header *)dmi_buf;
        p = dmi_buf + hdr->length;  /* points to data for SMBIOS Structure Type 0 */

        while (*p != 0 || *(p + 1) != 0) /* Skip data for Type 0*/
            p++;

        hdr = (struct dmi_header *)(p + 2);
        hdr->data = (uint8_t *)hdr;

        if (dmi_info_to_meta(hdr, meta) < 0) {
            free_null_ptr(meta->manufacturer);
            free_null_ptr(meta->product_name);
            free_null_ptr(meta->serial_number);
            free(dmi_buf);
            return -1;
        }

        free(dmi_buf);
        return 0;
    } else {
        printf("Unknown SMBIOS version\n");
        return -1;
    }
}

int get_dmi_system_info(struct meta_data *meta)
{
    int ret = 0;
    size_t size = 0x20;
    void *buf = NULL;

    if ((buf = read_file(0, &size, SYS_ENTRY_FILE)) == NULL)
        return -1;

    if (size >= 24) {
        if (att_smbios_decode(buf, SYS_TABLE_FILE, meta) < 0) {
            ret = -1;
            goto err;
        }

    } else {
        fprintf(stderr, "Non-stardard DMI entry size\n");
        ret = -1;
    }

err:
    free(buf);

    return ret;
}
