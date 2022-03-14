#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <fobnail-attester/meta.h>

#define SYS_CLASS_NET_PATH  "/sys/class/net"

/* TODO: Use this macro to print errors in this project */
#define PRINT_ERR_RET(msg, ...)                                     \
    do {                                                            \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        return -1;                                                  \
    } while (0)

static int obtain_mac_from_iface(const char *iface, uint8_t *dst_mac)
{
    int fd;
    struct ifreq ifr;
    unsigned char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    memcpy(dst_mac, mac, 6);

	return 0;
}

/**
 * Parse the path and obtain the PCI BDF from it
 */
static int get_bdf_from_path(const char *link_path, uint32_t *out_bdf)
{
    char *bdf;
    size_t bdf_str_len;
    char *colon1, *colon2, *dot, *slash1, *slash2, *null;
    uint32_t ret = 0UL;
    int x,y,z;

    if (strncmp(link_path, "/sys/devices/pci", sizeof("/sys/devices/pci") - 1) != 0)
        return -1;

    colon1 = strrchr(link_path, ':');
    slash1 = colon1;
    while (*slash1 && *slash1 != '/')
        slash1--;

    slash2 = strchr(colon1, '/');
    bdf_str_len =  slash2 - slash1 - 1;
    bdf = strndup(slash1 + 1, bdf_str_len);
    bdf[bdf_str_len] = '\0';

    colon1 = strchr(bdf, ':');
    colon1 += 1;
    colon2 = strchr(colon1, ':');
    null = colon2;
    colon2 += 1;
    *null = '\0';
    dot = strchr(colon2, '.');
    null = dot;
    dot += 1;
    *null = '\0';

    x = atoi(colon1 + 1);
    y = atoi(colon2);
    z = atoi(dot);

    ret |= z;
    ret |= y << 8;
    ret |= x << 16;

    free(bdf);
    *out_bdf = ret;
    return 0;
}

static int get_mac_addr(uint8_t *mac)
{
    DIR *d;
    char *link_buf;
    char link_path[1024];
    size_t link_buf_size = PATH_MAX;
    struct dirent *dir;

    struct bdf_t {
        char        iface[32];
        uint32_t    bdf_num;
    };

    struct bdf_t bdf = {
        .bdf_num = 0UL,
    };

    if (access(SYS_CLASS_NET_PATH, R_OK))
        PRINT_ERR_RET("ERR: No network on sysfs: %s\n", strerror(errno));

    link_buf = malloc(link_buf_size);
    if (!link_buf)
        PRINT_ERR_RET("ERR: Cannot allocate memory: %s\n", strerror(errno));

    if ((d = opendir(SYS_CLASS_NET_PATH)) == NULL)
        PRINT_ERR_RET("ERR: Cannot open directory %s\n", SYS_CLASS_NET_PATH);

    while ((dir = readdir(d)) != NULL) {
        uint32_t curr_bdf;
        struct stat sb;

        if (dir->d_name[0] == '.')
            continue;

        snprintf(link_path, 1024, "%s/%s", SYS_CLASS_NET_PATH, dir->d_name);
        if (lstat(link_path, &sb) < 0) {
            fprintf(stderr, "WARN: Cannot stat the path: %s\n", link_path);
            break;
        }

        if (!S_ISLNK(sb.st_mode))
            continue;

        memset(link_buf, 0, link_buf_size);
        readlink(link_path, link_buf, link_buf_size);

        /* Exclude virtual network devices */
        if (strstr(link_buf, "virtual"))
            continue;

        /* Convert path to absolute
         * Path is constructed by concatenating SYS_CLASS_NET_PATH with relative
         * path from readlink() so we need to allocate twice as much memory.
         */
        char relative_path[PATH_MAX*2];
        snprintf(relative_path, PATH_MAX *2, "%s/%s", SYS_CLASS_NET_PATH, link_buf);
        
        char canonical_path[PATH_MAX];
        if (!realpath(relative_path, canonical_path)) {
            fprintf(stderr, "Failed to resolve canonical path of \"%s\": %s\n", dir->d_name, strerror(errno));
            continue;
        }

        /* Ignore all network cards which are not connected to PCI */
        if (get_bdf_from_path(canonical_path, &curr_bdf) >= 0) {
            if (bdf.bdf_num == 0UL || bdf.bdf_num > curr_bdf) {
                bdf.bdf_num = curr_bdf;
                snprintf(bdf.iface, 32, "%s", (strrchr(link_buf, '/') + 1));
            }
        }
    }

    free(link_buf);
    closedir(d);

    if (bdf.bdf_num != 0) {
        obtain_mac_from_iface(bdf.iface, mac);
        return 0;
    } else {
        fprintf(stderr, "WARN: Cannot find any physical network interface in sysfs\n");
        return -1;
    }
}

int get_meta_data(struct meta_data *meta)
{
    meta->header_version = META_H_VERSION;

    if (get_mac_addr(meta->mac) < 0)
        return -1;

    printf("MAC: %2X:%2X:%2X:%2X:%2X:%2X\n",
            meta->mac[0], meta->mac[1], meta->mac[2], meta->mac[3], meta->mac[4], meta->mac[5]);

    return get_dmi_system_info(meta);
}

