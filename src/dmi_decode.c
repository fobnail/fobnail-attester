#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <fobnail-attester/meta.h>

struct dmi_header {
    uint8_t  type;
    uint8_t  length;
    uint16_t handle;
    uint8_t  *data;
};

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
        if (bp[i] < 32 || bp[i] >= 127)
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

static int att_smbios3_decode(uint8_t *buf, const char *devmem, struct meta_data *meta)
{
    size_t len;
    uint8_t *dmi_buf = NULL;

    /* Don't let checksum run beyond the buffer */
    if (buf[0x06] > 0x20) {
        fprintf(stderr,
            "Entry point length too large (%u bytes, expected %u).\n",
            (unsigned int)buf[0x06], 0x18U);
        return 0;
    }

    /* Some SMBIOS magic constants. I guess this is from specification. */
    len  = (uint32_t)((buf + 0x0C)[0] + ((buf + 0x0C)[1] << 8)
                     + ((buf + 0x0C)[2] << 16) + ((buf + 0x0C)[3] << 24));
 
    dmi_buf = read_file(0, &len, devmem);
    if (dmi_buf) {
        uint8_t *data, *next;
        struct dmi_header h;

        data = dmi_buf;
        while (data + 4 <= dmi_buf + len) {
            h.type = data[0];
            h.length = data[1];
            h.handle = data[2] + (data[3] << 8);
            h.data = data;

            if (h.type == 1) {
                uint8_t *sys_data = h.data;
                if (h.length < 0x08)
                    break;

                printf("Manufacturer >%s<\n", dmi_string(&h, sys_data[0x04]));
                printf("Product Name >%s<\n", dmi_string(&h, sys_data[0x05]));
                printf("Serial Number >%s<\n", dmi_string(&h, sys_data[0x07]));
                break;
            }
            next = data + h.length;
            while ((unsigned long)(next - dmi_buf + 1) < len && (next[0] != 0 || next[1] != 0))
                next++;

            next += 2; /* This is also some magic from dmidecode */
            /* Make sure the whole structure fits in the table */
            if ((unsigned long)(next - dmi_buf) > len)
                break;

            data = next;
        }

        free(dmi_buf);
    }

    return 1;
}

int get_dmi_system_info(struct meta_data *meta)
{
    size_t size;
    void *buf = NULL;

    size = 0x20;
    if ((buf = read_file(0, &size, SYS_ENTRY_FILE)) != NULL) {
        if (size >= 24 && memcmp(buf, "_SM3_", 5) == 0)
            att_smbios3_decode(buf, SYS_TABLE_FILE, meta);
    } else {
        fprintf(stderr, "Not supported yet. Currently only SMBIOS_3 is supported.\n");
        return -1;
    }

    free(buf);

    return 0;
}
