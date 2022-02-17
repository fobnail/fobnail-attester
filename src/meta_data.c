#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include <fobnail-attester/meta.h>

#define SYS_CLASS_NET_PATH  "/sys/class/net"

/* TODO: Use this macro to print errors in this project */
#define PRINT_ERR_RET(msg, ...)                                     \
    do {                                                            \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        return -1;                                                  \
    } while (0)

static int get_serial(const struct serial_number *sn)
{
    return 0;
}

static int get_mac_addr(const uint8_t *mac)
{
    DIR *d;
    struct dirent *dir;

    if (access(SYS_CLASS_NET_PATH, R_OK))
        PRINT_ERR_RET("No network on host: %s\n", strerror(errno));

    if ((d = opendir(SYS_CLASS_NET_PATH)) == NULL)
        PRINT_ERR_RET("Cannot open directory %s\n", SYS_CLASS_NET_PATH);

    while ((dir = readdir(d)) != NULL) {
        static int i;
        printf("dir%d: %s\n", i++, dir->d_name);
    }

    closedir(d);

    return 0;
}

int get_meta_data(const struct meta_data *meta)
{
    if (get_mac_addr(meta->mac) < 0)
        return -1;


    return 0;
}

